/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Reusable evaluator for compound condition handlers that aggregate child condition results.
 *
 * */
import { AccessControlError } from '../core';
import { ArrayUtil, CommonUtil } from '../utils';
import { ConditionUtil } from './index';

export class CompoundConditionEvaluator {
    static evaluate(
        args: any,
        context: any,
        combineSync: (results: boolean[]) => boolean
    ): boolean | Promise<boolean> {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        const argsType = CommonUtil.type(args);
        if (argsType !== 'array' && argsType !== 'object') {
            throw new AccessControlError('Compound condition expects type of args to be array or object');
        }

        const conditions = ArrayUtil.toArray(args);
        const evaluations = conditions.map((condition) => {
            return ConditionUtil.evaluate(condition, context);
        });

        if (CommonUtil.containsPromises(evaluations)) {
            return Promise.all(evaluations).then(combineSync);
        }

        return combineSync(evaluations as boolean[]);
    }
}
