import { jwtPayload } from "./jwt-payload.type";

export type jwtPayloadWithRefreshToken = jwtPayload & { refreshToken: string };
