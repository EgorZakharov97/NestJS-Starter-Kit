import { Exclude } from 'class-transformer';
import { Column, Entity, PrimaryColumn } from 'typeorm';
import { Role } from '../enums/role.enum';

@Entity('auth')
export class Auth {
  @PrimaryColumn()
  identity: string;

  @Column()
  @Exclude()
  password: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ type: 'text', default: Role.User })
  role: Role;

  @Column({ nullable: true })
  confirmationToken: string;

  @Column({ default: true })
  emailConfirmed: boolean;

  @Column({ nullable: true })
  resetPasswordToken: string;

  constructor(partial: Partial<Auth>) {
    Object.assign(this, partial);
  }
}
