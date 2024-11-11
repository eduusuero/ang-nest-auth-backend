import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPaylaod } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto';

@Injectable()
export class AuthService {


  constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ){}


  async create(createUserDto: CreateUserDto): Promise<User> {


    try{

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({ 
          password: bcryptjs.hashSync( password , 10 ),
          ...userData 
      
      });

      await newUser.save();

      const { password:_,...user} = newUser.toJSON();

      return user;  
    }
    catch(error){
      if(error.code === 11000){
        throw new BadRequestException(`${ createUserDto.email } ya existe!`)
      }
      throw new InternalServerErrorException('Otro error..')
    }
  }

  async register( registerDto: RegisterUserDto ): Promise<LoginResponse>{

    const user = await this.create( registerDto );

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }
  

  async login ( loginDto: LoginDto ): Promise<LoginResponse>{
    //AHORA HAY QUE VERIFICAR EL USUARIO
    const { email, password } = loginDto

    const user = await this.userModel.findOne({ email });

    if (!user){
      throw new UnauthorizedException('No son validas las credenciales');
    }

    if ( !bcryptjs.compareSync( password, user.password ) ){
      throw new UnauthorizedException('Password no valida');
    }
    //return 'Todo bien!';

    //Tomo el usuario menos su password para luego hacer el JWT
    const { password: _ , ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    }
  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ){
    const user = await this.userModel.findById( id );

    const { password, ...rest } = user.toJSON();

    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }


  getJwtToken( payload: JwtPaylaod ){

    const token = this.jwtService.sign(payload);

    return token;

  }

}
