/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Shared utility helpers for grant normalization, role expansion, permission evaluation, and data filtering.
 *
 * */
import { Notation } from 'notation';
import { matcher } from 'matcher';
import { ArrayUtil } from './array';
import { ConditionUtil } from '../conditions';
import { AccessControlError, IQueryInfo, IAccessInfo, ICondition } from '../core';
const cloneDeep = require('lodash.clonedeep');

export class CommonUtil {

    public static isStringOrArray(value: any): boolean {
        return typeof value === 'string' || ArrayUtil.isFilledStringArray(value);
    }

    public static eachKey(obj: any, callback: (key: string, index?: number) => void): void {
        return Object.keys(obj).forEach(callback);
    }

    public static someTrue(elements: boolean[]) {
        return elements.some((elm) => elm);
    }

    public static allTrue(elements: boolean[]) {
        return elements.every((elm) => elm);
    }

    public static allFalse(elements: boolean[]) {
        return elements.every((elm) => !elm);
    }

    public static anyMatch(strings: string | string[], patterns: string | string[]): boolean {
        const stringArray = ArrayUtil.toStringArray(strings);
        const patternArray = ArrayUtil.toStringArray(patterns);
        return matcher(stringArray, patternArray).length !== 0;
    }

    public static toExtendedJSON(o: any): string {
        return JSON.stringify(o, function (key, value) {
            if (typeof value === 'function') {
                return '/Function(' + value.toString() + ')/';
            }
            return value;
        });
    }

    public static fromExtendedJSON(json: string): any {
        return JSON.parse(json, function (key, value) {
            if (typeof value === 'string'
                && value.startsWith('/Function(')
                && value.endsWith(')/')) {
                value = value.substring(10, value.length - 2);
                return new Function('return ' + value)();
            }
            return value;
        });
    }

    public static containsPromises(elements: any[]) {
        return elements.some((elm) => {
            return elm && typeof (elm.then) === 'function' && Promise.resolve(elm) === elm;
        });
    }

    public static clone(o: any): object {
        return cloneDeep(o);
    }

    public static type(o: any): string {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    }

    public static hasDefined(o: any, propName: string): boolean {
        return Object.prototype.hasOwnProperty.call(o, propName) && o[propName] !== undefined;
    }

    /**
     *  Gets roles and extended roles in a flat array.
     */
    public static async getFlatRoles(grants: any, roles: string | string[], context?: any, skipConditions?: boolean): Promise<string[]> {
        roles = ArrayUtil.toStringArray(roles);
        if (!roles) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }

        let arr: string[] = roles.slice();
        for (const roleName of roles) {
            const roleItem: any = grants[roleName];
            if (!roleItem) {
                throw new AccessControlError(`Role not found: "${roleName}"`);
            }
            if (!roleItem.$extend) {
                continue;
            }

            const rolesMetCondition: string[] = [];
            const extendedRoleNames = Object.keys(roleItem.$extend);

            if (skipConditions) {
                arr = ArrayUtil.uniqConcat(arr, await this.getFlatRoles(grants, extendedRoleNames, context, skipConditions));
                continue;
            }

            for (const extendedRoleName of extendedRoleNames) {
                if (await ConditionUtil.evaluate(roleItem.$extend[extendedRoleName].condition, context)) {
                    rolesMetCondition.push(extendedRoleName);
                }
            }

            arr = ArrayUtil.uniqConcat(arr, await this.getFlatRoles(grants, rolesMetCondition, context, skipConditions));
        }
        return arr;
    }

    public static getFlatRolesSync(grants: any, roles: string | string[], context?: any, skipConditions?: boolean): string[] {
        roles = ArrayUtil.toStringArray(roles);
        if (!roles) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }

        let arr: string[] = roles.slice();
        for (const roleName of roles) {
            const roleItem: any = grants[roleName];
            if (!roleItem) {
                throw new AccessControlError(`Role not found: "${roleName}"`);
            }
            if (!roleItem.$extend) {
                continue;
            }

            const rolesMetCondition: string[] = [];
            const extendedRoleNames = Object.keys(roleItem.$extend);

            if (skipConditions) {
                arr = ArrayUtil.uniqConcat(arr, this.getFlatRolesSync(grants, extendedRoleNames, context, skipConditions));
                continue;
            }

            for (const extendedRoleName of extendedRoleNames) {
                const conditionResult = ConditionUtil.evaluate(roleItem.$extend[extendedRoleName].condition, context);
                if (typeof conditionResult !== 'boolean') {
                    throw new AccessControlError(`Expected the condition function should return boolean, but returning ${conditionResult}`);
                }
                if (conditionResult) {
                    rolesMetCondition.push(extendedRoleName);
                }
            }

            arr = ArrayUtil.uniqConcat(arr, this.getFlatRolesSync(grants, rolesMetCondition, context, skipConditions));
        }
        return arr;
    }

    public static normalizeGrantsObject(grants: any): any {
        const grantsCopy = this.clone(grants);
        for (const role in grantsCopy) {
            if (!grantsCopy[role].grants) {
                continue;
            }
            grantsCopy[role].grants.forEach((grant) => {
                ConditionUtil.validateCondition(grant.condition);
                grant.attributes = grant.attributes || ['*'];
            });
            grantsCopy[role].score = grantsCopy[role].score || 1;
        }
        return grantsCopy;
    }

    public static normalizeQueryInfo(query: IQueryInfo): IQueryInfo {
        const newQuery: IQueryInfo = this.clone(query);

        newQuery.role = ArrayUtil.toStringArray(newQuery.role);
        if (!ArrayUtil.isFilledStringArray(newQuery.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(newQuery.role)}`);
        }

        if (newQuery.resource) {
            if (typeof newQuery.resource !== 'string' || newQuery.resource.trim() === '') {
                throw new AccessControlError(`Invalid resource: "${newQuery.resource}"`);
            }
            newQuery.resource = newQuery.resource.trim();
        }

        if (newQuery.action) {
            if (typeof newQuery.action !== 'string' || newQuery.action.trim() === '') {
                throw new AccessControlError(`Invalid action: ${newQuery.action}`);
            }
        }

        return newQuery;
    }

    public static normalizeAccessInfo(access: IAccessInfo): IAccessInfo {
        const newAccess: IAccessInfo = this.clone(access);

        newAccess.role = ArrayUtil.toStringArray(newAccess.role);
        if (!ArrayUtil.isFilledStringArray(newAccess.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(newAccess.role)}`);
        }

        newAccess.resource = ArrayUtil.toStringArray(newAccess.resource);
        if (!ArrayUtil.isFilledStringArray(newAccess.resource)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(newAccess.resource)}`);
        }

        newAccess.action = ArrayUtil.toStringArray(newAccess.action);
        if (!ArrayUtil.isFilledStringArray(newAccess.action)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(newAccess.action)}`);
        }

        newAccess.attributes = !newAccess.attributes ? ['*'] : ArrayUtil.toStringArray(newAccess.attributes);

        return newAccess;
    }

    /**
     *  Used to re-set (prepare) the `attributes` of an `IAccessInfo` object
     *  when it's first initialized with e.g. `.grant()` or `.deny()` chain
     *  methods.
     *  @param {IAccessInfo} access
     *  @returns {IAccessInfo}
     */
    public static resetAttributes(access: IAccessInfo): IAccessInfo {
        if (!access.attributes || ArrayUtil.isEmptyArray(access.attributes)) {
            access.attributes = ['*'];
        }
        return access;
    }

    /**
     *  Checks whether the given access info can be committed to grants model.
     *  @param {IAccessInfo|IQueryInfo} info
     *  @returns {Boolean}
     */
    public static isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean {
        return this.hasDefined(info, 'role')
            && this.hasDefined(info, 'action')
            && this.hasDefined(info, 'resource');
    }

    /**
     *  Commits the given `IAccessInfo` object to the grants model.
     *  CAUTION: if attributes is omitted, it will default to `['*']` which
     *  means "all attributes allowed".
     *  @param {Any} grants
     *  @param {IAccessInfo} access
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    public static commitToGrants(grants: any, access: IAccessInfo): void {
        access = this.normalizeAccessInfo(access);
        (access.role as Array<string>).forEach((role: string) => {
            grants[role] = grants[role] || { score: 1 };
            grants[role].grants = grants[role].grants || [];
            ConditionUtil.validateCondition(access.condition);
            grants[role].grants.push({
                resource: access.resource,
                action: access.action,
                attributes: access.attributes,
                condition: access.condition
            });
        });
    }

    public static async getUnionGrantsOfRoles(grants: any, query: IQueryInfo): Promise<IAccessInfo[]> {
        this.ensureGrantsSet(grants);
        const normalizedQuery = this.normalizeQueryInfo(query);
        const roles = await this.getFlatRoles(grants, normalizedQuery.role, normalizedQuery.context, normalizedQuery.skipConditions);
        return this.flattenRoleGrants(grants, roles);
    }

    public static getUnionGrantsOfRolesSync(grants: any, query: IQueryInfo): IAccessInfo[] {
        this.ensureGrantsSet(grants);
        const normalizedQuery = this.normalizeQueryInfo(query);
        const roles = this.getFlatRolesSync(grants, normalizedQuery.role, normalizedQuery.context, normalizedQuery.skipConditions);
        return this.flattenRoleGrants(grants, roles);
    }

    public static async getUnionResourcesOfRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        query.skipConditions = this.shouldSkipConditions(query);
        return this.collectUnionFieldAsync(grants, query, 'resource');
    }

    public static getUnionResourcesOfRolesSync(grants: any, query: IQueryInfo): string[] {
        query.skipConditions = this.shouldSkipConditions(query);
        return this.collectUnionFieldSync(grants, query, 'resource');
    }

    public static async getUnionActionsOfRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        query.skipConditions = this.shouldSkipConditions(query);
        return this.collectUnionFieldAsync(grants, query, 'action', (grant, normalizedQuery) => {
            return this.anyMatch(normalizedQuery.resource, grant.resource);
        });
    }

    public static getUnionActionsOfRolesSync(grants: any, query: IQueryInfo): string[] {
        query.skipConditions = this.shouldSkipConditions(query);
        return this.collectUnionFieldSync(grants, query, 'action', (grant, normalizedQuery) => {
            return this.anyMatch(normalizedQuery.resource, grant.resource);
        });
    }

    /**
     *  When more than one role is passed, we union the permitted attributes
     *  for all given roles; so we can check whether "at least one of these
     *  roles" have the permission to execute this action.
     *  e.g. `can(['admin', 'user']).createAny('video')`
     *
     *  @param {Any} grants
     *  @param {IQueryInfo} query
     *
     *  @returns {Array<String>} - Array of union'ed attributes.
     */
    public static async getUnionAttrsOfRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        return this.collectUnionFieldAsync(grants, query, 'attributes', (grant, normalizedQuery) => {
            return this.anyMatch(normalizedQuery.resource, grant.resource)
                && this.anyMatch(normalizedQuery.action, grant.action);
        });
    }

    public static getUnionAttrsOfRolesSync(grants: any, query: IQueryInfo): string[] {
        return this.collectUnionFieldSync(grants, query, 'attributes', (grant, normalizedQuery) => {
            return this.anyMatch(normalizedQuery.resource, grant.resource)
                && this.anyMatch(normalizedQuery.action, grant.action);
        });
    }

    public static async filterGrantsAllowing(grants: IAccessInfo[], query: IQueryInfo): Promise<IAccessInfo[]> {
        if (query.skipConditions) {
            return grants;
        }

        const matchingGrants: IAccessInfo[] = [];
        for (const grant of grants) {
            if (await ConditionUtil.evaluate(grant.condition, query.context)) {
                matchingGrants.push(grant);
            }
        }
        return matchingGrants;
    }

    public static filterGrantsAllowingSync(grants: IAccessInfo[], query: IQueryInfo): IAccessInfo[] {
        if (query.skipConditions) {
            return grants;
        }

        const matchingGrants: IAccessInfo[] = [];
        for (const grant of grants) {
            const conditionResult = query.skipConditions || ConditionUtil.evaluate(grant.condition, query.context);
            if (typeof conditionResult !== 'boolean') {
                throw new AccessControlError(`Expected the condition function should return boolean, but returning ${conditionResult}`);
            }
            if (conditionResult) {
                matchingGrants.push(grant);
            }
        }
        return matchingGrants;
    }

    public static async areGrantsAllowing(grants: IAccessInfo[], query: IQueryInfo): Promise<boolean> {
        if (!grants) {
            return false;
        }

        let result = false;
        for (const grant of grants) {
            result = result || (
                this.anyMatch(query.resource, grant.resource)
                && this.anyMatch(query.action, grant.action)
                && (query.skipConditions || await ConditionUtil.evaluate(grant.condition, query.context))
            );
        }
        return result;
    }

    public static areGrantsAllowingSync(grants: IAccessInfo[], query: IQueryInfo): boolean {
        if (!grants) {
            return false;
        }

        let result = false;
        for (const grant of grants) {
            const conditionResult = query.skipConditions || ConditionUtil.evaluate(grant.condition, query.context);
            if (typeof conditionResult !== 'boolean') {
                throw new AccessControlError(`Expected the condition function should return boolean, but returning ${conditionResult}`);
            }
            result = result || (
                this.anyMatch(query.resource, grant.resource)
                && this.anyMatch(query.action, grant.action)
                && (query.skipConditions || conditionResult)
            );
        }
        return result;
    }

    public static async areExtendingRolesAllowing(roleExtensionObject: any, allowingRoles: any, query: IQueryInfo): Promise<boolean> {
        if (!roleExtensionObject) {
            return false;
        }

        let result = false;
        for (const roleName in roleExtensionObject) {
            result = result || (
                allowingRoles[roleName]
                && (query.skipConditions || await ConditionUtil.evaluate(roleExtensionObject[roleName].condition, query.context))
            );
        }
        return result;
    }

    public static areExtendingRolesAllowingSync(roleExtensionObject: any, allowingRoles: any, query: IQueryInfo): boolean {
        if (!roleExtensionObject) {
            return false;
        }

        let result = false;
        for (const roleName in roleExtensionObject) {
            const conditionResult = query.skipConditions || ConditionUtil.evaluate(roleExtensionObject[roleName].condition, query.context);
            if (typeof conditionResult !== 'boolean') {
                throw new AccessControlError(`Expected the condition function should return boolean, but returning ${conditionResult}`);
            }
            result = result || (allowingRoles[roleName] && (query.skipConditions || conditionResult));
        }
        return result;
    }

    public static async getAllowingRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        this.ensureGrantsSet(grants);

        const allowingRoles = {};
        const sortedRoles = Object.keys(grants).sort((role1, role2) => {
            return grants[role1].score - grants[role2].score;
        });

        for (const role of sortedRoles) {
            allowingRoles[role] = await this.areGrantsAllowing(grants[role].grants, query)
                || await this.areExtendingRolesAllowing(grants[role].$extend, allowingRoles, query);
        }

        return Object.keys(allowingRoles).filter((role) => {
            return allowingRoles[role];
        });
    }

    public static getAllowingRolesSync(grants: any, query: IQueryInfo): string[] {
        this.ensureGrantsSet(grants);

        const allowingRoles = {};
        const sortedRoles = Object.keys(grants).sort((role1, role2) => {
            return grants[role1].score - grants[role2].score;
        });

        for (const role of sortedRoles) {
            allowingRoles[role] = this.areGrantsAllowingSync(grants[role].grants, query)
                || this.areExtendingRolesAllowingSync(grants[role].$extend, allowingRoles, query);
        }

        return Object.keys(allowingRoles).filter((role) => {
            return allowingRoles[role];
        });
    }

    /**
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {Array<string>} roles - Roles to be checked.
     *  @returns {Array<String>} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    public static getNonExistentRoles(grants: any, roles: string[]): string[] {
        const non: string[] = [];
        for (const role of roles) {
            if (!Object.prototype.hasOwnProperty.call(grants, role)) {
                non.push(role);
            }
        }
        return non;
    }

    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *
     *  @param {Any} grants
     *  @param {String|Array<String>} roles
     *         Role(s) to be extended.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a role does not exist, it will be automatically
     *         created.
     *
     *  @param {String|Array<String>} extenderRoles
     *         Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a extender role does not exist, it will throw.
     *  @param {ICondition} [condition]
     *         Condition to be used for extension of roles. Only extends
     *         the roles when condition is met
     *
     *  @throws {Error}
     *          If a role is extended by itself or a non-existent role.
     */
    public static extendRole(grants: any, roles: string | string[], extenderRoles: string | string[], condition?: ICondition): void {
        ConditionUtil.validateCondition(condition);
        CommonUtil.extendRoleSync(grants, roles, extenderRoles, condition);
    }

    public static extendRoleSync(grants: any, roles: string | string[], extenderRoles: string | string[], condition?: ICondition): void {
        ConditionUtil.validateCondition(condition);

        const arrExtRoles: string[] = ArrayUtil.toStringArray(extenderRoles);
        if (!arrExtRoles) {
            throw new AccessControlError(`Invalid extender role(s): ${JSON.stringify(extenderRoles)}`);
        }

        const nonExistentExtRoles: string[] = this.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new AccessControlError(`Cannot extend with non-existent role(s): "${nonExistentExtRoles.join(', ')}"`);
        }

        roles = ArrayUtil.toStringArray(roles);
        if (!roles) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }

        const allExtendingRoles = this.getFlatRolesSync(grants, arrExtRoles, null, true);
        const extensionScore = allExtendingRoles.reduce((total, role) => {
            return total + grants[role].score;
        }, 0);

        roles.forEach((role: string) => {
            if (allExtendingRoles.indexOf(role) >= 0) {
                throw new AccessControlError(`Attempted to extend role "${role}" by itself.`);
            }
            grants[role] = grants[role] || { score: 1 };
            grants[role].score += extensionScore;
            grants[role].$extend = grants[role].$extend || {};
            arrExtRoles.forEach((extRole) => {
                grants[role].$extend[extRole] = grants[role].$extend[extRole] || {};
                grants[role].$extend[extRole].condition = condition;
            });
        });
    }

    public static matchesAllElement(values: any, predicateFn: (elm) => boolean): boolean {
        values = ArrayUtil.toArray(values);
        return values.every(predicateFn);
    }

    public static matchesAnyElement(values: any, predicateFn: (elm) => boolean): boolean {
        values = ArrayUtil.toArray(values);
        return values.some(predicateFn);
    }

    public static filter(object: any, attributes: string[]): any {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        const notation = new Notation(object);
        return notation.filter(attributes).value;
    }

    public static filterAll(arrOrObj: any, attributes: string[]): any {
        if (!Array.isArray(arrOrObj)) {
            return this.filter(arrOrObj, attributes);
        }
        return arrOrObj.map((o) => {
            return this.filter(o, attributes);
        });
    }

    private static shouldSkipConditions(query: IQueryInfo): boolean {
        return !!(query.skipConditions || !query.context);
    }

    private static ensureGrantsSet(grants: any): void {
        if (!grants) {
            throw new AccessControlError('Grants are not set.');
        }
    }

    private static flattenRoleGrants(grants: any, roles: string[]): IAccessInfo[] {
        return roles
            .filter((role) => {
                return grants[role] && grants[role].grants;
            })
            .map((role) => {
                return grants[role].grants;
            })
            .reduce((allGrants, roleGrants) => {
                return allGrants.concat(roleGrants);
            }, []);
    }

    private static async collectUnionFieldAsync(
        grants: any,
        query: IQueryInfo,
        field: 'resource' | 'action' | 'attributes',
        grantFilter?: (grant: IAccessInfo, normalizedQuery: IQueryInfo) => boolean
    ): Promise<string[]> {
        const normalizedQuery = this.normalizeQueryInfo(query);
        const unionGrants = await this.getUnionGrantsOfRoles(grants, normalizedQuery);
        const matchingGrants = grantFilter ? unionGrants.filter((grant) => grantFilter(grant, normalizedQuery)) : unionGrants;
        const allowedGrants = await this.filterGrantsAllowing(matchingGrants, normalizedQuery);
        return this.unionGrantField(allowedGrants, field);
    }

    private static collectUnionFieldSync(
        grants: any,
        query: IQueryInfo,
        field: 'resource' | 'action' | 'attributes',
        grantFilter?: (grant: IAccessInfo, normalizedQuery: IQueryInfo) => boolean
    ): string[] {
        const normalizedQuery = this.normalizeQueryInfo(query);
        const unionGrants = this.getUnionGrantsOfRolesSync(grants, normalizedQuery);
        const matchingGrants = grantFilter ? unionGrants.filter((grant) => grantFilter(grant, normalizedQuery)) : unionGrants;
        const allowedGrants = this.filterGrantsAllowingSync(matchingGrants, normalizedQuery);
        return this.unionGrantField(allowedGrants, field);
    }

    private static unionGrantField(grants: IAccessInfo[], field: 'resource' | 'action' | 'attributes'): string[] {
        return grants
            .map((grant) => {
                return ArrayUtil.toStringArray(grant[field]);
            })
            .reduce(Notation.Glob.union, []);
    }
}
