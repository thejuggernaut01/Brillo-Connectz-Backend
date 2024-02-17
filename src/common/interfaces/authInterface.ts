import { Request } from "express";

// Extend the Request type
export interface CustomRequest<T = any> extends Request {
  user?: T;
}
