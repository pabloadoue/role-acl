/**
 * Fork from: tensult/role-acl:develop
 * Refactored and updated by: Pablo Adoue Peralta
 *
 * Custom error type for access-control validation and runtime failures.
 *
 * */
/**
 *  Error class specific to `AccessControl`.
 *  @readonly
 *  @name AccessControl.Error
 *  @class
 *  @static
 */
class AccessControlError extends Error {
    public name: string = 'AccessControlError';
    constructor(public message: string = '') {
        super(message);
        // http://stackoverflow.com/a/41429145/112731
        Object.setPrototypeOf(this, AccessControlError.prototype);
    }
}

export { AccessControlError };
