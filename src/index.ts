// 1. Imports (always at the top)
import express from 'express';
import bcrypt from 'bcrypt';
import { prisma } from './prisma';
import jwt from 'jsonwebtoken'; 
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

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

const ROLE_RANK = { VIEWER: 1, MEMBER: 2, ADMIN: 3, OWNER: 4 } as const;
type RoleName = keyof typeof ROLE_RANK;

const requireRole = (minRole: RoleName) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const organizationId = String(req.params.orgId);

    const membership = await prisma.membership.findUnique({
      where: {
        userId_organizationId: { userId: res.locals.userId, organizationId },
      },
    });

    if (!membership) {
      res.status(403).json({ message: 'You are not a member of this organization' });
      return;
    }

    if (ROLE_RANK[membership.role] < ROLE_RANK[minRole]) {
      res.status(403).json({ message: 'Your role does not allow this action' });
      return;
    }

    res.locals.organizationId = organizationId;
    res.locals.role = membership.role;
    next();
  };
};

app.get('/organizations', requireAuth, async (req, res) => {
  const memberships = await prisma.membership.findMany({
    where: { userId: res.locals.userId },
    include: { organization: true },
  });

  res.status(200).json(
    memberships.map((m) => ({
      id: m.organization.id,
      name: m.organization.name,
      role: m.role,
    }))
  );
});

app.get('/organizations/:orgId/members', requireAuth, requireRole('VIEWER'), async (req, res) => {
  const members = await prisma.membership.findMany({
    where: { organizationId: res.locals.organizationId },
    select: { role: true, user: { select: { id: true, email: true } } },
  });

  res.status(200).json(members);
});

app.delete('/organizations/:orgId', requireAuth, requireRole('OWNER'), async (req, res) => {
  await prisma.$transaction([
    prisma.membership.deleteMany({ where: { organizationId: res.locals.organizationId } }),
    prisma.organization.delete({ where: { id: res.locals.organizationId } }),
  ]);

  res.status(204).send();
});

const INVITABLE_ROLES = ['ADMIN', 'MEMBER', 'VIEWER'];

app.post('/organizations/:orgId/invitations', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const { email, role } = req.body;

  if (typeof email !== 'string' || !email.includes('@') || !INVITABLE_ROLES.includes(role)) {
    res.status(400).json({ message: 'A valid email and a role of ADMIN, MEMBER or VIEWER are required' });
    return;
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const invitation = await prisma.invitation.create({
    data: {
      email: email.trim().toLowerCase(),
      role,
      token,
      expiresAt,
      organizationId: res.locals.organizationId,
    },
  });

  res.status(201).json({ id: invitation.id, email: invitation.email, role: invitation.role, token, expiresAt });
});

app.post('/invitations/accept', requireAuth, async (req, res) => {
  const { token } = req.body;

  if (typeof token !== 'string') {
    res.status(400).json({ message: 'Token is required' });
    return;
  }

  const invitation = await prisma.invitation.findUnique({ where: { token } });

  if (!invitation) {
    res.status(404).json({ message: 'Invitation not found' });
    return;
  }

  if (invitation.acceptedAt || invitation.expiresAt < new Date()) {
    res.status(410).json({ message: 'Invitation has expired or was already used' });
    return;
  }

  const user = await prisma.user.findUnique({ where: { id: res.locals.userId } });

  if (!user || user.email.toLowerCase() !== invitation.email) {
    res.status(403).json({ message: 'This invitation was sent to a different email' });
    return;
  }

  try {
    await prisma.$transaction([
      prisma.membership.create({
        data: { userId: user.id, organizationId: invitation.organizationId, role: invitation.role },
      }),
      prisma.invitation.update({
        where: { id: invitation.id },
        data: { acceptedAt: new Date() },
      }),
    ]);
  } catch (error) {
    if ((error as { code?: string }).code === 'P2002') {
      res.status(409).json({ message: 'You are already a member of this organization' });
      return;
    }
    res.status(500).json({ message: 'Something went wrong' });
    return;
  }

  res.status(200).json({ organizationId: invitation.organizationId, role: invitation.role });
});

// 4. Start the server (always last)
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});