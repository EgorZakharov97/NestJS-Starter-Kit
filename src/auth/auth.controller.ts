import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  UseGuards,
  Res,
  Param,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { LocalAuthGuard } from './guards/local.guard';
import { Request, Response } from 'express';
import { JwtAuthGuard } from './guards/jwt.guard';
import { Auth } from './entities/auth.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('local/login')
  async loginLocal(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = await this.authService.login(req.user as Auth);
    res.cookie('jwt', token, { httpOnly: true });
    return req.user;
  }

  @Post('local/register')
  async registerLocal(@Body() newUser: CreateAuthDto) {
    return await this.authService.register(newUser);
  }

  @Post('local/reset/:token')
  async resetPassword(
    @Param('token') token: string,
    @Body('password') password: string,
  ) {
    this.authService.resetPassword(token, password);
  }

  @Post('local/reset')
  sendResetPassword(@Body('email') email: string) {
    return this.authService.sendResetPassword(email);
  }

  @Get('local/confirm')
  async confirmEmail(@Query('token') token: string) {
    return await this.authService.confirmEmail(token);
  }

  @UseGuards(JwtAuthGuard)
  @Get('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    this.authService.setTokenAsCookie(res, '');
    return true;
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req: Request) {
    return req.user;
  }
}
