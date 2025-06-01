import {
    BadGatewayException,
  BadRequestException,
  ConflictException,
  Injectable,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { PrismaService } from "../prisma/prisma.service";
import { CreateUserDto, SignInUserDto } from "../users/dto";
import * as bcrypt from "bcrypt";
import { User } from "../../generated/prisma";
import { Response } from "express";

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService
  ) {}

  async UsergenerateToken(user: User) {
    const payload = {
      id: user.id,
      is_active: user.is_active,
      email: user.email,
      name: user.name
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
     const {name, email, password, confirm_password} = createUserDto;
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
    return { message: "singup", accessToken:tokens.accessToken}

  }
  async updateRefreshToken(id: number, refresh_token: string) {
    await this.prismaService.user.update({
        where: {id},
        data: { hashed_refresh_token: refresh_token}
    })
  }

  async signin(signinUserDto: SignInUserDto, res: Response){
    const { password, email } = signinUserDto

    const user = await this.prismaService.user.findUnique({
        where: { email }
    })
    if(!user){
        throw new BadGatewayException("email yoki password xato 1")
    }
    const passwordMatched = await bcrypt.compare(password, user.hashed_password)
    if(!passwordMatched){
        throw new BadGatewayException("email yoki password xato 2");
    }

    const tokens = await this.UsergenerateToken(user)

    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7)
    await this.updateRefreshToken(user.id, hashed_refresh_token)

    res.cookie("refreshToken", tokens.refreshToken, {
        maxAge: Number(process.env.COOKIE_TIME),
        httpOnly: true,
      })
    return { message: "Sign in", accessToken:tokens.accessToken}

    }
}
