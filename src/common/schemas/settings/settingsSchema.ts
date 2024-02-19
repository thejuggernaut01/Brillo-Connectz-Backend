import { z } from "zod";

export const changePasswordSchema = z.object({
  password: z
    .string({ required_error: "Password is required" })
    .min(6, { message: "Password must be at least 6 characters long" }),
});

export const updateUsernameSchema = z.object({
  username: z.string({ required_error: "Username is required" }),
});

export const changeEmailSchema = z.object({
  email: z
    .string({ required_error: "Email is required" })
    .email("Invalid email"),
});
