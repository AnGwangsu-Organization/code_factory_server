import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { User } from '../user/entities/user.entity';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { CacheService } from '../cache/cache.service';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private cacheService: CacheService,
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  verifyToken(token: string) {
    return this.jwtService.verify(token);
  }

  async rotateAccessToken(refreshToken: string): Promise<string> {
    const decoded = this.jwtService.verify(refreshToken);

    return this.signToken(
      {
        username: decoded.username,
        id: decoded.sub,
      },
      false,
    );
  }

  signToken(user: any, isRefreshToken: boolean): string {
    const payload = {
      username: user.username,
      sub: user.id,
      type: isRefreshToken ? 'refresh' : 'access',
    };

    return this.jwtService.sign(payload, {
      expiresIn: isRefreshToken ? '1d' : '300s',
    });
  }

  async authenticate(username: string, password: string): Promise<User | null> {
    const user = await this.userService.findByUsername(username);

    if (!user) {
      return null;
    }

    if (user.password !== password) {
      return null;
    }

    return user;
  }

  async login(dto: LoginDto) {
    console.log(dto);
    const { username, password } = dto;

    const user = await this.authenticate(username, password);

    if (!user) {
      console.log('아이디 또는 비밀번호가 틀림')
      throw new ForbiddenException('아이디 또는 비밀번호가 틀렸습니다.');
    }

    return {
      refreshToken: this.signToken(user, true),
      accessToken: this.signToken(user, false),
    };
  }
}
