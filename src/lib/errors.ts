/**
 * Application-level error carrying an HTTP status code.
 *
 * Messages on `AppError` are considered safe to return to the client; anything
 * thrown that is not an `AppError` is reported as a generic 500 by the central
 * error handler so internal details never leak.
 */
export class AppError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details?: unknown;

  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "AppError";
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export class ValidationError extends AppError {
  constructor(message = "Request validation failed", details?: unknown) {
    super(400, "VALIDATION_ERROR", message, details);
    this.name = "ValidationError";
  }
}

export class BadRequestError extends AppError {
  constructor(message = "Bad request", code = "BAD_REQUEST", details?: unknown) {
    super(400, code, message, details);
    this.name = "BadRequestError";
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = "Authentication required", code = "UNAUTHORIZED") {
    super(401, code, message);
    this.name = "UnauthorizedError";
  }
}

export class ForbiddenError extends AppError {
  constructor(message = "Access forbidden", code = "FORBIDDEN", details?: unknown) {
    super(403, code, message, details);
    this.name = "ForbiddenError";
  }
}

export class NotFoundError extends AppError {
  constructor(message = "Resource not found", code = "NOT_FOUND") {
    super(404, code, message);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends AppError {
  constructor(message: string, code = "CONFLICT") {
    super(409, code, message);
    this.name = "ConflictError";
  }
}

export class TooManyRequestsError extends AppError {
  constructor(message = "Too many requests. Please try again later.", code = "RATE_LIMITED") {
    super(429, code, message);
    this.name = "TooManyRequestsError";
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message: string, code = "SERVICE_UNAVAILABLE") {
    super(503, code, message);
    this.name = "ServiceUnavailableError";
  }
}

