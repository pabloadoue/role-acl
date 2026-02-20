/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Evaluates compound OR conditions and returns true when at least one child condition matches.
 *
 * */
import { IConditionFunction } from './IConditionFunction';
import { CompoundConditionEvaluator } from './CompoundConditionEvaluator';
import { CommonUtil } from '../utils';

/**
 * Or condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class OrCondition implements IConditionFunction {

    evaluate(args?: any, context?: any): boolean | Promise<boolean> {
        return CompoundConditionEvaluator.evaluate(args, context, CommonUtil.someTrue);
    }
}

