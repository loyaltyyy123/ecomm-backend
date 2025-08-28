const { z } = require('zod');
const RegisterSchema = z.object({
    name: z.string().trim().min(2).max(60),
    email: z.string().email().trim().toLowerCase(),
    password: z.string().min(8, 'Min 8 chars').max(128)
    .regex(/[A-Z]/, 'Include an uppercase')
    .regex(/[a-z]/, 'Include a lowercase')
    .regex(/[0-9]/, 'Include a number')
    .regex(/[^A-Za-z0-9]/, 'Include a symbol'),
    role: z.enum(['user', 'admin']).optional()
});
const LoginSchema = z.object({
    email: z.string().email().trim().toLowerCase(),
    password: z.string().min(8)
});
module.exports = { RegisterSchema, LoginSchema };