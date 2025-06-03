import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import { CreateUserDto, SignInUserDto } from "../users/dto";
import { Request, Response } from "express";
import { ResponseFilds } from "../common/types";
import { refreshTokenGuard } from "../common/guards";
import { GetCurrentUser, GetCurrentUserId } from "../common/decorators";

@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("signup")
  async signup(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<ResponseFilds> {
    return this.authService.signup(createUserDto, res);
  }

  @HttpCode(200)
  @Post("signin")
  async signin(
    @Body() signinUserDto: SignInUserDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<ResponseFilds> {
    return this.authService.signin(signinUserDto, res);
  }

  // @Post("user-refresh")
  // async UserrefreshToken(
  //   @Req() req: Request,
  //   @Res({ passthrough: true }) res: Response
  // ) {
  //   return this.authService.UserrefreshToken(req, res);
  // }

  @UseGuards(refreshTokenGuard)
  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser("refreshToken") refreshToken: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<ResponseFilds> {
    return this.authService.refreshToken(+userId, refreshToken, res);
  }

  @UseGuards(refreshTokenGuard)
  @Post("signout")
  @HttpCode(HttpStatus.OK)
  singout(
    @GetCurrentUserId() userId: number,
    @Res({ passthrough: true }) res: Response
  ): Promise<boolean> {
    return this.authService.singout(+userId, res);
  }
}
