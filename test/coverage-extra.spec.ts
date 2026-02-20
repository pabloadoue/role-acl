const AccessControl = require('../src').AccessControl;
const { CommonUtil } = require('../src/utils/common');
const { ArrayUtil } = require('../src/utils/array');
const { ConditionUtil, getValueByPath } = require('../src/conditions/util');
const { Query } = require('../src/core/Query');
const { AccessControlError } = require('../src/core/AccessControlError');
const { EqualsCondition } = require('../src/conditions/EqualsCondition');
const { NotEqualsCondition } = require('../src/conditions/NotEqualsCondition');
const { ListContainsCondition } = require('../src/conditions/ListContainsCondition');
const { StartsWithCondition } = require('../src/conditions/StartsWithCondition');
const { TrueCondition } = require('../src/conditions/TrueCondition');
const { CompoundConditionEvaluator } = require('../src/conditions/CompoundConditionEvaluator');
export {};

describe('Coverage Suite: Utilities and Conditions', () => {
  beforeEach(() => {
    ConditionUtil.resetCustomConditionFunctions();
  });

  it('covers ArrayUtil branches', () => {
    expect(new ArrayUtil()).toBeDefined();
    expect(ArrayUtil.toStringArray(['a'])).toEqual(['a']);
    expect(ArrayUtil.toStringArray('a,b;c')).toEqual(['a', 'b', 'c']);
    expect(ArrayUtil.toStringArray(123)).toBeNull();

    expect(ArrayUtil.toArray(['x'])).toEqual(['x']);
    expect(ArrayUtil.toArray('x')).toEqual(['x']);

    expect(ArrayUtil.isFilledStringArray(['a', 'b'])).toBeTrue();
    expect(ArrayUtil.isFilledStringArray(['a', ''])).toBeFalse();
    expect(ArrayUtil.isFilledStringArray(null)).toBeFalse();

    expect(ArrayUtil.isEmptyArray([])).toBeTrue();
    expect(ArrayUtil.isEmptyArray(['x'])).toBeFalse();

    expect(ArrayUtil.uniqConcat(['a'], ['a', 'b'])).toEqual(['a', 'b']);
    expect(ArrayUtil.subtractArray(['a', 'b'], ['b'])).toEqual(['a']);
  });

  it('covers CommonUtil primitives and serialization', () => {
    expect(CommonUtil.isStringOrArray('a')).toBeTrue();
    expect(CommonUtil.isStringOrArray(['a'])).toBeTrue();
    expect(CommonUtil.isStringOrArray([1])).toBeFalse();

    const keys: string[] = [];
    CommonUtil.eachKey({ a: 1, b: 2 }, (k) => keys.push(k));
    expect(keys).toEqual(['a', 'b']);

    expect(CommonUtil.someTrue([false, true])).toBeTrue();
    expect(CommonUtil.allTrue([true, true])).toBeTrue();
    expect(CommonUtil.allFalse([false, false])).toBeTrue();

    expect(CommonUtil.anyMatch(['read:any'], ['read:*'])).toBeTrue();

    const obj = { n: 1, fn: (x) => x + 1 };
    const serialized = CommonUtil.toExtendedJSON(obj);
    const restored = CommonUtil.fromExtendedJSON(serialized);
    expect(typeof restored.fn).toBe('function');
    expect(restored.fn(1)).toBe(2);

    expect(CommonUtil.containsPromises([Promise.resolve(true)])).toBeTrue();
    expect(CommonUtil.containsPromises([1, 2])).toBeFalse();

    const cloned: any = CommonUtil.clone({ a: 1 });
    expect(cloned).toEqual({ a: 1 });
    expect(CommonUtil.type([])).toBe('array');
    expect(CommonUtil.hasDefined({ a: undefined }, 'a')).toBeFalse();
    expect(CommonUtil.hasDefined({ a: 1 }, 'a')).toBeTrue();
  });

  it('covers normalization and commit branches', () => {
    const grants = CommonUtil.normalizeGrantsObject({
      admin: { grants: [{ resource: 'video', action: 'read' }] },
      guest: {}
    });
    expect(grants.admin.score).toBe(1);
    expect(grants.admin.grants[0].attributes).toEqual(['*']);

    expect(() => CommonUtil.normalizeQueryInfo({ role: null })).toThrowError(AccessControlError);
    expect(() => CommonUtil.normalizeQueryInfo({ role: 'user', resource: 123 })).toThrowError(AccessControlError);
    expect(() => CommonUtil.normalizeQueryInfo({ role: 'user', action: 123 })).toThrowError(AccessControlError);
    expect(CommonUtil.normalizeQueryInfo({ role: 'user', resource: ' video ' }).resource).toBe('video');

    expect(() => CommonUtil.normalizeAccessInfo({ role: null, resource: 'x', action: 'read' })).toThrowError(AccessControlError);
    expect(() => CommonUtil.normalizeAccessInfo({ role: 'user', resource: null, action: 'read' })).toThrowError(AccessControlError);
    expect(() => CommonUtil.normalizeAccessInfo({ role: 'user', resource: 'x', action: null })).toThrowError(AccessControlError);

    const normalized = CommonUtil.normalizeAccessInfo({ role: 'user', resource: 'video', action: 'read' });
    expect(normalized.attributes).toEqual(['*']);

    expect(CommonUtil.resetAttributes({} as any).attributes).toEqual(['*']);
    expect(CommonUtil.resetAttributes({ attributes: ['id'] } as any).attributes).toEqual(['id']);
    expect(CommonUtil.isInfoFulfilled({ role: 'u', action: 'a', resource: 'r' } as any)).toBeTrue();
    expect(CommonUtil.isInfoFulfilled({ role: 'u' } as any)).toBeFalse();

    const g: any = {};
    CommonUtil.commitToGrants(g, { role: 'user', resource: 'video', action: 'read', attributes: ['*'] });
    expect(g.user.grants.length).toBe(1);
  });

  it('covers role flatten, union and allow calculations', async () => {
    const grants: any = {
      user: {
        score: 1,
        grants: [{ resource: 'video', action: 'read', attributes: ['*'] }],
        $extend: {
          editor: { condition: { Fn: 'TRUE' } }
        }
      },
      editor: {
        score: 2,
        grants: [{ resource: 'video', action: 'update', attributes: ['title'] }]
      }
    };

    expect(await CommonUtil.getFlatRoles(grants, 'user', {})).toContain('editor');
    expect(CommonUtil.getFlatRolesSync(grants, 'user', {}, true)).toContain('editor');
    await expectAsync(CommonUtil.getFlatRoles(grants, null, {})).toBeRejected();
    expect(() => CommonUtil.getFlatRolesSync(grants, null, {})).toThrowError(AccessControlError);

    await expectAsync(CommonUtil.getFlatRoles(grants, 'missing')).toBeRejected();
    expect(() => CommonUtil.getFlatRolesSync(grants, 'missing')).toThrowError(AccessControlError);

    const query: any = { role: 'user', resource: 'video', action: 'read', context: {} };
    expect((await CommonUtil.getUnionGrantsOfRoles(grants, query)).length).toBeGreaterThan(0);
    expect(CommonUtil.getUnionGrantsOfRolesSync(grants, query).length).toBeGreaterThan(0);

    expect((await CommonUtil.getUnionResourcesOfRoles(grants, query))).toContain('video');
    expect(CommonUtil.getUnionResourcesOfRolesSync(grants, query)).toContain('video');

    expect((await CommonUtil.getUnionActionsOfRoles(grants, query)).length).toBeGreaterThan(0);
    expect(CommonUtil.getUnionActionsOfRolesSync(grants, query).length).toBeGreaterThan(0);

    expect((await CommonUtil.getUnionAttrsOfRoles(grants, query)).length).toBeGreaterThan(0);
    expect(CommonUtil.getUnionAttrsOfRolesSync(grants, query).length).toBeGreaterThan(0);

    expect((await CommonUtil.filterGrantsAllowing(grants.user.grants, { skipConditions: true } as any)).length).toBe(1);
    expect(CommonUtil.filterGrantsAllowingSync(grants.user.grants, { skipConditions: true } as any).length).toBe(1);

    expect(await CommonUtil.areGrantsAllowing(null as any, query)).toBeFalse();
    expect(CommonUtil.areGrantsAllowingSync(null as any, query)).toBeFalse();

    expect(await CommonUtil.areExtendingRolesAllowing(null, {}, query)).toBeFalse();
    expect(CommonUtil.areExtendingRolesAllowingSync(null, {}, query)).toBeFalse();

    expect((await CommonUtil.getAllowingRoles(grants, query)).length).toBeGreaterThan(0);
    expect(CommonUtil.getAllowingRolesSync(grants, query).length).toBeGreaterThan(0);

    expect(CommonUtil.getNonExistentRoles(grants, ['user', 'missing'])).toEqual(['missing']);

    const g2: any = { admin: { score: 1, grants: [] }, user: { score: 1, grants: [] } };
    CommonUtil.extendRoleSync(g2, 'user', 'admin');
    expect(g2.user.$extend.admin).toEqual({ condition: undefined });
    expect(() => CommonUtil.extendRoleSync(g2, 'user', 'missing')).toThrowError(AccessControlError);
    expect(() => CommonUtil.extendRoleSync(g2, 'user', null)).toThrowError(AccessControlError);
    expect(() => CommonUtil.extendRoleSync(g2, null, 'admin')).toThrowError(AccessControlError);
    await expectAsync(CommonUtil.getUnionGrantsOfRoles(null, query)).toBeRejected();
    expect(() => CommonUtil.getUnionGrantsOfRolesSync(null, query)).toThrowError(AccessControlError);
    expect(() => CommonUtil.getFlatRolesSync({
      a: { $extend: { b: { condition: async () => true } } },
      b: {}
    }, 'a', {})).toThrowError(AccessControlError);

    expect(CommonUtil.matchesAllElement([1, 2], (x) => x > 0)).toBeTrue();
    expect(CommonUtil.matchesAnyElement([1, 2], (x) => x === 2)).toBeTrue();

    expect(CommonUtil.filter({ a: 1, b: 2 }, ['a'])).toEqual({ a: 1 });
    expect(CommonUtil.filter({}, [])).toEqual({});
    expect(CommonUtil.filterAll([{ a: 1 }, { a: 2 }], ['a']).length).toBe(2);
    expect(() => CommonUtil.areGrantsAllowingSync([{
      condition: async () => true,
      resource: 'video',
      action: 'read',
      attributes: ['*']
    }], query)).toThrowError(AccessControlError);
    expect(() => CommonUtil.areExtendingRolesAllowingSync({
      admin: { condition: async () => true }
    }, { admin: true }, query)).toThrowError(AccessControlError);
  });

  it('covers condition util registration, validation, evaluation, and json path', async () => {
    expect(new ConditionUtil()).toBeDefined();
    expect(new CompoundConditionEvaluator()).toBeDefined();
    expect(() => ConditionUtil.registerCustomConditionFunction('', () => true)).toThrowError(AccessControlError);

    spyOn(console, 'warn');
    ConditionUtil.registerCustomConditionFunction('custom:x', () => true);
    ConditionUtil.registerCustomConditionFunction('custom:x', () => false);
    expect(console.warn).toHaveBeenCalled();

    ConditionUtil.resetCustomConditionFunctions();
    ConditionUtil.setCustomConditionFunctions({
      y: () => true
    });
    expect(typeof ConditionUtil.getCustomConditionFunctions()['custom:y']).toBe('function');

    ConditionUtil.validateCondition(undefined);
    ConditionUtil.validateCondition(() => true);
    expect(() => ConditionUtil.validateCondition('custom:missing')).toThrowError(AccessControlError);
    expect(() => ConditionUtil.validateCondition({ Fn: 'UNKNOWN' })).toThrowError(AccessControlError);

    expect(ConditionUtil.evaluate(undefined as any, {})).toBeTrue();
    expect(ConditionUtil.evaluate((ctx) => !!ctx.ok, { ok: true })).toBeTrue();

    ConditionUtil.registerCustomConditionFunction('custom:yes', () => true);
    expect(ConditionUtil.evaluate('custom:yes', {})).toBeTrue();

    expect(() => ConditionUtil.evaluate('custom:nope', {})).toThrowError(AccessControlError);
    expect(() => ConditionUtil.evaluate({} as any, {})).toThrowError(AccessControlError);

    expect(ConditionUtil.evaluate({ Fn: 'TRUE' }, {})).toBeTrue();

    ConditionUtil.registerCustomConditionFunction('custom:gt', (ctx, args) => ctx.v > args.v);
    expect(ConditionUtil.evaluate({ Fn: 'custom:gt', args: { v: 1 } }, { v: 2 })).toBeTrue();
    expect(() => ConditionUtil.evaluate({ Fn: 'custom:none' }, {})).toThrowError(AccessControlError);
    expect(ConditionUtil.evaluate(42 as any, {})).toBeFalse();

    const ctx = { a: { b: [1, [2]] }, p: 'prefix-value' };
    expect(ConditionUtil.getValueByPath(ctx, '$.a.b')).toEqual([1, 2]);
    expect(getValueByPath(ctx, '$.a.b')).toEqual([1, 2]);
    expect(ConditionUtil.getValueByPath(ctx, 'literal')).toBe('literal');

    ConditionUtil.registerCustomConditionFunction('custom:asyncTrue', async () => true);
    const asyncEval = CompoundConditionEvaluator.evaluate([{ Fn: 'custom:asyncTrue' }], {}, (res) => res.every(Boolean));
    expect(await asyncEval).toBeTrue();
    expect(CompoundConditionEvaluator.evaluate(undefined, {}, () => true)).toBeTrue();
    expect(CompoundConditionEvaluator.evaluate({ Fn: 'TRUE' }, null, () => true)).toBeFalse();
    expect(() => CompoundConditionEvaluator.evaluate('invalid', {}, () => true)).toThrowError(AccessControlError);
  });

  it('covers condition classes edge branches', () => {
    const equals = new EqualsCondition();
    const notEquals = new NotEqualsCondition();
    const listContains = new ListContainsCondition();
    const startsWith = new StartsWithCondition();
    const trueCondition = new TrueCondition();

    expect(equals.evaluate(undefined, {})).toBeTrue();
    expect(equals.evaluate({ a: 1 }, undefined)).toBeFalse();
    expect(() => equals.evaluate('x' as any, {})).toThrowError(AccessControlError);

    expect(notEquals.evaluate(undefined, {})).toBeTrue();
    expect(notEquals.evaluate({ a: 1 }, undefined)).toBeFalse();
    expect(() => notEquals.evaluate('x' as any, {})).toThrowError(AccessControlError);

    expect(listContains.evaluate(undefined, {})).toBeTrue();
    expect(listContains.evaluate({ a: [1] }, undefined)).toBeFalse();
    expect(() => listContains.evaluate('x' as any, {})).toThrowError(AccessControlError);

    expect(startsWith.evaluate(undefined, {})).toBeTrue();
    expect(startsWith.evaluate({ a: ['x'] }, undefined)).toBeFalse();
    expect(() => startsWith.evaluate('x' as any, {})).toThrowError(AccessControlError);

    expect(trueCondition.evaluate()).toBeTrue();
  });

  it('covers AccessControl and Query less-used methods', async () => {
    const ac = new AccessControl();
    ac.grant('user').execute('read').on('video');
    ac.allow('user').execute('update').on('video');
    ac.reset();
    ac.grant('user').execute('read').on('video');

    expect(ac.getRoles()).toContain('user');
    expect(ac.hasRole('user')).toBeTrue();
    expect(ac.access('user')).toBeDefined();
    expect(AccessControl.isAccessControlError(new AccessControlError('x'))).toBeTrue();

    const q = new Query(ac.getGrants(), 'user');
    q.role('user').resource('video').with({}).execute('read').skipConditions(true);
    const perm = q.on('video');
    expect(perm).toBeDefined();

    const qsync = new Query(ac.getGrants(), 'user').sync().role('user').resource('video').execute('read');
    const perSync = qsync.on('video', true);
    expect(perSync.granted).toBeTrue();

    const json = ac.toJSON();
    const restored = AccessControl.fromJSON(json);
    expect(new Query(ac.getGrants(), { role: 'user', action: 'read', resource: 'video' } as any)).toBeDefined();
    expect((await restored.can('user').execute('read').on('video')).granted).toBeTrue();

    expect(await ac.allowedGrants({ role: 'user' })).toBeDefined();
    expect(ac.allowedGrantsSync({ role: 'user' })).toBeDefined();

    expect(await ac.allowingRoles({ role: 'user', resource: 'video', action: 'read', context: {} })).toContain('user');
    expect(ac.allowingRolesSync({ role: 'user', resource: 'video', action: 'read', context: {} })).toContain('user');

    expect((await ac.allowedActions({ role: 'user', resource: 'video', context: {} })).length).toBeGreaterThan(0);
    expect(ac.allowedActionsSync({ role: 'user', resource: 'video', context: {} }).length).toBeGreaterThan(0);

    expect((await ac.allowedResources({ role: 'user', action: 'read', context: {} })).length).toBeGreaterThan(0);
    expect(ac.allowedResourcesSync({ role: 'user', action: 'read', context: {} }).length).toBeGreaterThan(0);

    expect((await ac.permission({ role: 'user', resource: 'video', action: 'read', context: {} })).granted).toBeTrue();
    expect(ac.permissionSync({ role: 'user', resource: 'video', action: 'read', context: {} }).granted).toBeTrue();
  });
});
