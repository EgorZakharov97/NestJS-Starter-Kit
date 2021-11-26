import { IsString, MinLength } from "class-validator";

export class CreateAuthDto {
  @IsString()
  @MinLength(6)
  identity: string;

  @IsString()
  @MinLength(6)
  password: string;
}
