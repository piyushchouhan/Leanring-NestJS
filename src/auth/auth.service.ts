import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService{

    constructor(
        private prisma : PrismaService,
        private jwt : JwtService,
        private config : ConfigService
    ){}

    async signin(dto : AuthDto){
        // Find the email entered by the user
        const user = 
        await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        // If the email is not found, throw an error
        if(!user){
            throw new ForbiddenException('Email does not exist')
        }

        // compare the password entered by the user with the hash in the database
        const isPasswordValid = await argon.verify(user.hash, dto.password);

        // If the password is incorrect, throw an error
        if(!isPasswordValid){
            throw new ForbiddenException('Password is incorrect');
        }

        // return the user
        delete user.hash;
        return this.signinToken(user.id, user.email);
    }

    async signup(dto: AuthDto){
        // genereate hash the password
        const hash = await argon.hash(dto.password);

       try{
         // save the new user to the database
        const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash
            }
        });
        delete user.hash;

        // return the user
        return this.signinToken(user.id, user.email);
        
        }catch(error){
            if(error instanceof PrismaClientKnownRequestError){
                if(error.code === 'P2002'){
                    throw new ForbiddenException('Email already exists');
                }
            }
            throw error;
        }
    }

    // function to generate a token
    async signinToken(userId : number, email:string): Promise<{access_token : string}>{
        const payload ={
            sub : userId,
            email,
        };

        const secret = this.config.get('JWT_SECRET');

        const token = await this.jwt.signAsync( payload,{
            expiresIn: '15m',
            secret: 'secret'
        });

        return {
            access_token: token
        }
    }
}
