import {
  createParamDecorator,
  ExecutionContext,
  ForbiddenException,
} from "@nestjs/common";
import { jwtPayload, jwtPayloadWithRefreshToken } from "../types";

export const GetCurrentUser = createParamDecorator(
  (data: keyof jwtPayloadWithRefreshToken, context: ExecutionContext) => {
    const requset = context.switchToHttp().getRequest();
    const user = requset.user as jwtPayload;
    console.log(user);
    console.log(data);
    
    if (!user) {
      throw new ForbiddenException("Token noto'g'ri");
    }
    
    if(!data){
      return user
    }

    return user[data]
  }
);

