/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Evaluates compound AND conditions and returns true only when all child conditions match.
 *
 * */
import { IConditionFunction } from './IConditionFunction';
import { CompoundConditionEvaluator } from './CompoundConditionEvaluator';
import { CommonUtil } from '../utils';

/**
 * And condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class AndCondition implements IConditionFunction {

     evaluate(args?: any, context?: any):boolean | Promise<boolean> {
        return CompoundConditionEvaluator.evaluate(args, context, CommonUtil.allTrue);
    }
}

