import { ForbiddenException, Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { JwtFromRequestFunction, Strategy } from "passport-jwt";
import { jwtPayload, jwtPayloadWithRefreshToken } from "../types";

export const cookieExtraction: JwtFromRequestFunction = (req: Request) => {
  console.log(req.cookies);
  if (req && req.cookies) {
    return req.cookies["refreshToken"];
  }
  return null;
};

@Injectable()
export class RefreshTokenCookieStrategy extends PassportStrategy(
  Strategy,
  "refresh-jwt"
) {
  constructor() {
    super({
      jwtFromRequest: cookieExtraction,
      secretOrKey: process.env.REFRESH_TOKEN_KEY!,
      passReqToCallback: true,
    });
  }
  validate(req: Request, payload: jwtPayload): jwtPayloadWithRefreshToken {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      throw new ForbiddenException("refresh token noto'gri");
    }
    return { ...payload, refreshToken };
  }
}
