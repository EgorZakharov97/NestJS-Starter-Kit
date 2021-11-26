import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateAuthDto } from './dto/create-auth.dto';
import { Auth } from './entities/auth.entity';
import * as CryptoJS from 'crypto-js';
import { randomBytes } from 'crypto';
import { MailerService } from '@nestjs-modules/mailer';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Auth)
    private readonly authRepository: Repository<Auth>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailerService: MailerService,
  ) {}

  async register(dto: CreateAuthDto): Promise<Auth> {
    const existing = await this.findOne(dto.identity);
    if (existing)
      throw new BadRequestException('User with this username already exists');

    const auth = this.authRepository.create({
      identity: dto.identity,
      password: await this.getPasswordHash(dto.password),
    });
    return await this.authRepository.save(auth);
  }

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.findOne(username);
    if (!user)
      throw new BadRequestException('User and password does not match');
    const hashed = await this.getPasswordHash(pass);
    if (user.password !== hashed)
      throw new BadRequestException('User and password does not match');
    return user;
  }

  async login(auth: Auth) {
    const payload = { identity: auth.identity, role: auth.role };
    return this.jwtService.sign(payload);
  }

  private generateIdentityToken(): string {
    return randomBytes(10).toString('hex');
  }

  async sendRegistrationConfirmationEmail(auth: Auth) {
    const identifier = await this.generateIdentityToken();

    auth.confirmationToken = identifier;

    const emailOptions = {
      to: auth.identity,
      subject: 'Email Confirmation',
      html: `<h2>Hello from App</h2>
        <p>To finalize registration please confirm your email.</p><a href="${this.configService.get(
          'HOST',
        )}/confirm.html?token=${identifier}">Confirm Email</a>`,
    };

    this.mailerService
      .sendMail(emailOptions)
      .catch((e) => {
        console.error(e);
      })
      .then(() =>
        console.log(`Email confirmation was sent to ${auth.identity}`),
      );

    return this.authRepository.save(auth);
  }

  async confirmEmail(token: string): Promise<Auth> {
    const auth = await this.authRepository.findOne({
      confirmationToken: token,
    });

    if (!auth)
      throw new NotFoundException(
        'We could not found user with this confirmation token. Please contact support for manual confirmation',
      );

    auth.emailConfirmed = true;
    auth.confirmationToken = null;
    return this.authRepository.save(auth);
  }

  async sendResetPassword(identity: string) {
    const identifier = await this.generateIdentityToken();
    const auth = await this.authRepository.findOne({ identity });

    if (!auth) throw new NotFoundException('This email is not registered');

    auth.resetPasswordToken = identifier;
    this.authRepository.save(auth);

    const emailOptions = {
      to: auth.identity,
      subject: 'App Password Reset',
      html: `<h2>Hello from App</h2>
        <p>Here is your link to restore the password.</p><a href="${this.configService.get(
          'HOST',
        )}/new-password.html?token=${identifier}">Reset Password</a>`,
    };

    this.mailerService
      .sendMail(emailOptions)
      .catch((e) => {
        console.error(e);
      })
      .then(() =>
        console.log(`Email with password reset was sent to ${auth.identity}`),
      );
  }

  setTokenAsCookie(res: Response, token: string) {
    res.cookie('JWT', token, {
      secure: true,
      httpOnly: true,
      domain: this.configService.get('DOMAIN'),
      path: '/',
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<Auth> {
    const auth = await this.authRepository.findOne({
      resetPasswordToken: token,
    });

    if (!auth)
      throw new NotFoundException(
        'User with this confirmation token does not exist. Please, try again or contact support for manual help',
      );

    const hashedPwd = await this.getPasswordHash(newPassword);
    auth.password = hashedPwd;
    auth.resetPasswordToken = null;
    return await this.authRepository.save(auth);
  }

  private async getPasswordHash(password: string) {
    const hash = CryptoJS.HmacSHA256(
      password,
      this.configService.get('AUTH_PASSPHRASE'),
    );
    return CryptoJS.enc.Base64.stringify(hash);
  }

  private async findOne(identity: string): Promise<Auth | undefined> {
    return this.authRepository.findOne({ identity });
  }
}
