import {
  BadGatewayException,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { PrismaService } from "../prisma/prisma.service";
import { CreateUserDto, SignInUserDto } from "../users/dto";
import * as bcrypt from "bcrypt";
import { User } from "../../generated/prisma";
import { Request, Response } from "express";
import { jwtPayload, ResponseFilds, Tokens } from "../common/types";
import { use } from "passport";

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService
  ) {}

  async UsergenerateToken(user: User): Promise<Tokens> {
    const payload: jwtPayload = {
      id: user.id,
      is_active: user.is_active,
      email: user.email,
      // name: user.name,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  }

  async signup(createUserDto: CreateUserDto, res: Response) {
    const { name, email, password, confirm_password } = createUserDto;
    const condinate = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (condinate) {
      throw new ConflictException("Bunday email mavjud");
    }
    if (password !== confirm_password) {
      throw new BadRequestException("Parollar mos emas");
    }
    const hashed_password = await bcrypt.hash(password, 7);
    const user = await this.prismaService.user.create({
      data: { name, email, hashed_password },
    });

    const tokens = await this.UsergenerateToken(user);

    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);
    await this.updateRefreshToken(user.id, hashed_refresh_token);
    res.cookie("refreshToken", tokens.refreshToken),
      {
        maxAge: Number(process.env.COOKIE_TIME),
        httpOnly: true,
      };
    return { message: "singup", accessToken: tokens.accessToken, id: user.id };
  }
  async updateRefreshToken(id: number, refresh_token: string) {
    await this.prismaService.user.update({
      where: { id },
      data: { hashed_refresh_token: refresh_token },
    });
  }

  async signin(signinUserDto: SignInUserDto, res: Response) {
    const { password, email } = signinUserDto;

    const user = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (!user) {
      throw new BadGatewayException("email yoki password xato 1");
    }
    const passwordMatched = await bcrypt.compare(
      password,
      user.hashed_password
    );
    if (!passwordMatched) {
      throw new BadGatewayException("email yoki password xato 2");
    }

    const tokens = await this.UsergenerateToken(user);

    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);
    await this.updateRefreshToken(user.id, hashed_refresh_token);

    res.cookie("refreshToken", tokens.refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    return { message: "Sign in", id: user.id, accessToken: tokens.accessToken };
  }

  // async UserrefreshToken(req: Request, res: Response) {
  //   const refresh_token = req.cookies["refreshToken"];

  //   if (!refresh_token) {
  //     throw new ForbiddenException("Refresh token yo'q");
  //   }

  //   const users = await this.prismaService.user.findMany({
  //     where: {
  //       hashed_refresh_token: {
  //         not: null,
  //       },
  //     },
  //   });

  //   const user = users.find((user) =>
  //     bcrypt.compareSync(refresh_token, user.hashed_refresh_token!)
  //   );

  //   if (!user) {
  //     throw new ForbiddenException("Refresh token noto'g'ri");
  //   }

  //   const tokens = await this.UsergenerateToken(user);
  //   const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);

  //   await this.updateRefreshToken(user.id, hashed_refresh_token);

  //   res.cookie("refresh_token", tokens.refreshToken, {
  //     maxAge: Number(process.env.COOKIE_TIME),
  //     httpOnly: true,
  //   });

  //   return {
  //     message: "Token refresh qilindi",

  //     accessToken: tokens.accessToken,
  //   };
  // }

  async refreshToken(
    userId: number,
    refreshToken: string,
    res: Response
  ): Promise<ResponseFilds> {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });
    if (!user || !user.hashed_refresh_token)
      throw new ForbiddenException("Access Denied1");
    const rtMatches = await bcrypt.compare(
      refreshToken,
      user.hashed_refresh_token
    );
    if (!rtMatches) throw new ForbiddenException("Access Denied2");
    const tokens: Tokens = await this.UsergenerateToken(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);
    await this.updateRefreshToken(user.id, hashed_refresh_token);
    res.cookie("refreshToken", tokens.refreshToken, {
      maxAge: +process.env.COOKIE_TIME!,
      httpOnly: true,
    });
    return {
      message: "Tokenlar yangilandi",
      id: user.id,
      accessToken: tokens.accessToken,
    };
  }

  async singout(
    userId: number, res: Response
  ): Promise<boolean> {
    const user = await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashed_refresh_token: {
          not: null,
        },
      },
      data: {
        hashed_refresh_token: null
      },
    })
    if(!user) throw new ForbiddenException("Access Denied")
      res.clearCookie("refreshToken")
    return true
  }
}
