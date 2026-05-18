import { NextAuthOptions } from "next-auth";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@auth/prisma-adapter";
import prisma from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { loginSchema } from "@/lib/validations";

export const authOptions: NextAuthOptions = {
    adapter: PrismaAdapter(prisma) as any,
    providers: [
        GoogleProvider({
            clientId: process.env.GOOGLE_CLIENT_ID || "",
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
        }),
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "email" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials) {
                const parsed = loginSchema.safeParse(credentials);
                if (!parsed.success) {
                    throw new Error(parsed.error.errors[0].message);
                }

                const user = await prisma.user.findUnique({
                    where: { email: parsed.data.email }
                });

                // User doesn't exist or registered with Google (no password)
                if (!user || !user.password) {
                    throw new Error("User not found or uses OAuth");
                }

                const isPasswordValid = await bcrypt.compare(parsed.data.password, user.password);

                if (!isPasswordValid) {
                    throw new Error("Invalid Credentials");
                }

                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                return user as any;
            }
        })
    ],
    session: {
        strategy: "jwt",
    },
    callbacks: {
        async session({ session, token }) {
            if (session.user && token.sub) {
                session.user.id = token.sub; // Attach user ID from JWT token to session
            }
            return session;
        },
        async jwt({ token, user }) {
            if (user) {
                token.sub = user.id;
            }
            return token;
        },
    },
};
