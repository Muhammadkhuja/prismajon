import {
  createParamDecorator,
  ExecutionContext,
  ForbiddenException,
} from "@nestjs/common";
import { jwtPayload } from "../types";

export const GetCurrentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext): number => {
    const requset = context.switchToHttp().getRequest();
    const user = requset.user as jwtPayload;
    if (!user) {
      throw new ForbiddenException("Token noto'g'ri");
    }
    console.log("user", user);

    return user.id;
  }
);
