/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Condition handler that always evaluates to true.
 *
 * */
import { IConditionFunction } from './IConditionFunction';

/**
 * True condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class TrueCondition implements IConditionFunction {
    evaluate() {
        return true;
    }
}