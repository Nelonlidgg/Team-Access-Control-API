// 1. Imports (always at the top)
import express from 'express';
import bcrypt from 'bcrypt';
import { prisma } from './prisma';

// 2. Create the app and set up middleware
const app = express();
const PORT = 3000;
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

// 4. Start the server (always last)
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});