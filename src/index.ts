// 1. Imports (always at the top)
import express from 'express';
import bcrypt from 'bcrypt';
import { prisma } from './prisma';
import jwt from 'jsonwebtoken'; 
import { Request, Response, NextFunction } from 'express';

// 2. Create the app and set up middleware
const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is not set in .env');
}
app.use(express.json());

// 3. Routes
app.get('/', (req, res) => {
  res.send('Server is alive!');
});

app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, password: hashedPassword },
    });

    res.status(201).json({ id: user.id, email: user.email });
  } catch(error) {
    if ((error as { code?: string }).code === 'P2002') {
      res.status(409).json({ message: 'Email already in use' });
      return;
    }
    res.status(500).json({ message: 'Something went wrong' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    res.status(401).json({ message: 'Invalid email or password' });
    return;
  }

  const passwordMatches = await bcrypt.compare(password, user.password);

  if (!passwordMatches) {
    res.status(401).json({ message: 'Invalid email or password' });
    return;
  }
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

  res.status(200).json({ message: 'Login successful', token });
});

const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer')) {
    res.status(401).json({ message: 'Missing token' });
    return;
  }

  const token = header.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: string };
    res.locals.userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

app.get('/me', requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: res.locals.userId },
    select: { id: true, email: true, createdAt: true },
  });

  res.status(200).json(user);
});

app.post('/organizations', requireAuth, async (req, res) => {
  const { name } = req.body;

  if (typeof name !== 'string' || name.trim() === '') {
    res.status(400).json({ message: 'Organization name is required' });
    return;
  }

  const organization = await prisma.organization.create({
    data: {
      name: name.trim(),
      memberships: {
        create: { userId: res.locals.userId, role: 'OWNER' },
      },
    },
  });

  res.status(201).json({ id: organization.id, name: organization.name });
});

// 4. Start the server (always last)
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});