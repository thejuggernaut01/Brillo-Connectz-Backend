import { z } from "zod";

const isValidPhoneNumber = (phoneNumber: string) => {
  // Remove non-digit characters
  const cleanedNumber = phoneNumber.replace(/\D/g, "");

  // Allow at least 10 digits
  return /^\d{10,}$/.test(cleanedNumber);
};

export const createAccountSchema = z.object({
  email: z
    .string({ required_error: "Email is required" })
    .email("Invalid email"),
  password: z
    .string({ required_error: "Password is required" })
    .min(6, { message: "Password must be at least 6 characters long" }),
  phoneNumber: z
    .string({ required_error: "Phone number is required" })
    .refine(isValidPhoneNumber, {
      message: "Invalid phone number format",
    }),
  interests: z.array(z.string()).refine((array) => array.length > 0, {
    message: "At least one interest is required",
  }),
});

export const verifyEmailSchema = z.object({
  token: z.string({ required_error: "token is required" }),
});

export const resendEmailSchema = z.object({
  email: z
    .string({ required_error: "Email is required" })
    .email("Invalid email"),
});

export const loginSchema = z.object({
  email: z
    .string({ required_error: "Email is required" })
    .email("Invalid email")
    .optional(),
  password: z
    .string({ required_error: "Password is required" })
    .min(6, { message: "Password must be at least 6 characters long" }),
  phoneNumber: z
    .string({ required_error: "Phone number is required" })
    .refine(isValidPhoneNumber, {
      message: "Invalid phone number format",
    })
    .optional(),
});

export const forgotPasswordSchema = z.object({
  email: z
    .string({ required_error: "Email is required" })
    .email("Invalid email"),
});

export const updatePasswordSchema = z.object({
  password: z
    .string({ required_error: "Password is required" })
    .min(6, { message: "Password must be at least 6 characters long" }),
  token: z.string({ required_error: "token is required" }),
});
