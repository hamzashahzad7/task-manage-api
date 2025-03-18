const express = require("express");
const app = express();
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// const { PrismaClient } = require("@prisma/client");
const dotenv = require("dotenv");
dotenv.config();

// Enable CORS for all origins
app.use(cors({
  origin: '*',  // Allow requests from all origins
  methods: ['GET', 'POST', 'PUT', 'DELETE'],  // Allow specific HTTP methods
  allowedHeaders: ['Content-Type', 'Authorization'],  // Allow specific headers
}));
const prisma = require("./config/prisma-config");


// Middleware to parse JSON bodies
app.use(express.json());

// Create admin if no admin user exists
const createAdminIfNotExists = async () => {
  const existingAdmin = await prisma.user.findFirst({
    where: {
      role: "admin", // Check if any user has the 'admin' role
    },
  });

  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash("admin123", 10); // Default admin password
    const admin = await prisma.user.create({
      data: {
        username: "admin", // Default admin username
        password: hashedPassword,
        role: "admin", // Role 'admin'
      },
    });
    console.log("Admin user created:", admin.username);
  }
};

// Initialize admin on first run
createAdminIfNotExists();

// Utility function to generate JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    {
      expiresIn: "1d",
    }
  );
};

// API: Register User
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  const existingUser = await prisma.user.findUnique({
    where: { username },
  });

  if (existingUser) {
    return res.status(400).json({ error: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: {
      username,
      password: hashedPassword,
      role: "user", // Default role is 'user'
    },
  });

  const token = generateToken(user);
  res.status(201).json({ token, role: user.role });
});

// API: Login User
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await prisma.user.findUnique({
    where: { username },
  });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(400).json({ error: "Invalid credentials" });

  const token = generateToken(user);
  res.status(200).json({ token, role: user.role });
});

// Middleware: Auth Check (to protect routes)
const authenticate = (handler) => async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Get token from Authorization header

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach decoded user data to request
    return handler(req, res);
  } catch (error) {
    return res.status(401).json({ error: "Unauthorized" });
  }
};

// API: Create Task (Admin only)
// app.post(
//   "/api/task",
//   authenticate(async (req, res) => {
//     const { title, description, dueDate, priority, status, project } = req.body;

//     // Check if user is admin
//     if (req.user.role !== "admin") {
//       return res.status(403).json({ error: "Access denied, admin required" });
//     }

//     const task = await prisma.task.create({
//       data: {
//         title,
//         description,
//         dueDate: new Date(dueDate),
//         priority,
//         status,
//         project,
//         userId: req.user.id,
//       },
//     });

//     res.status(201).json(task);
//   })
// );

// API: Create Task (Standard User)
app.post(
  '/api/task',
  authenticate(async (req, res) => {
    const { title, description, dueDate, priority, status, project } = req.body;

    try {
      // Ensure the task is associated with the logged-in user
      const task = await prisma.task.create({
        data: {
          title,
          description,
          dueDate: new Date(dueDate),
          priority,
          status,
          project,
          userId: req.user.id, // Link task to the logged-in user
        },
      });

      res.status(201).json(task);
    } catch (err) {
      res.status(500).json({ error: 'Error creating task' });
    }
  })
);

// API: Update Task (Standard User)
app.put(
  '/api/task/:taskId',
  authenticate(async (req, res) => {
    const { taskId } = req.params;
    const { title, description, dueDate, priority, status, project } = req.body;

    try {
      // Only allow users to update their own tasks
      const task = await prisma.task.findUnique({ where: { id: Number(taskId) } });
      if (task.userId !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'You can only update your own tasks' });
      }

      const updatedTask = await prisma.task.update({
        where: { id: Number(taskId) },
        data: {
          title,
          description,
          dueDate: new Date(dueDate),
          priority,
          status,
          project,
        },
      });

      res.status(200).json(updatedTask);
    } catch (err) {
      res.status(500).json({ error: 'Error updating task' });
    }
  })
);

// API: Delete Task (Standard User)
app.delete(
  '/api/task/:taskId',
  authenticate(async (req, res) => {
    const { taskId } = req.params;

    try {
      // Only allow users to delete their own tasks
      const task = await prisma.task.findUnique({ where: { id: Number(taskId) } });
      if (task.userId !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'You can only delete your own tasks' });
      }

      await prisma.task.delete({
        where: { id: Number(taskId) },
      });

      res.status(200).json({ message: 'Task deleted successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Error deleting task' });
    }
  })
);

// API: Get All Tasks (Admin only)
app.get(
  '/api/tasks',
  authenticate(async (req, res) => {
    if (req.user.role === 'admin') {
      // Admin can view all tasks
      const tasks = await prisma.task.findMany();
      return res.status(200).json(tasks);
    } else {
      // Standard user can only view their own tasks
      const tasks = await prisma.task.findMany({
        where: { userId: req.user.id },
      });
      return res.status(200).json(tasks);
    }
  })
);


// API: Get Tasks for Standard User
app.get(
  "/api/tasks",
  authenticate(async (req, res) => {
    const tasks = await prisma.task.findMany({
      where: { userId: req.user.id }, // Only fetch tasks belonging to the logged-in user
    });
    res.status(200).json(tasks);
  })
);

// API: Get All Users (Admin only)
app.get(
  "/api/users",
  authenticate(async (req, res) => {
    // Only allow access to admins
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied, admin required" });
    }

    try {
      // Fetch all users' data
      const users = await prisma.user.findMany({
        select: {
          id: true,
          username: true,
          role: true,
          // Add other fields you want to include
        },
      });

      // Return the users' data
      res.status(200).json(users);
    } catch (err) {
      res.status(500).json({ error: "Error fetching users" });
    }
  })
);


// admin side only
// API: Get All Users (Admin only)
app.get(
  '/api/admin/users',
  authenticate(async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'You do not have permission to view users' });
    }

    try {
      const users = await prisma.user.findMany({
        select: {
          id: true,
          username: true,
          role: true,
          // Add other fields you want to expose
        },
      });
      res.status(200).json(users);
    } catch (err) {
      res.status(500).json({ error: 'Error fetching users' });
    }
  })
);

// API: Create User (Admin only)
app.post(
  '/api/admin/user',
  authenticate(async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'You do not have permission to create a user' });
    }

    const { username, password, role } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = await prisma.user.create({
        data: {
          username,
          password: hashedPassword,
          role, // Admin can assign role ('user' or 'admin')
        },
      });
      res.status(201).json(newUser);
    } catch (err) {
      res.status(500).json({ error: 'Error creating user' });
    }
  })
);

// API: Update User (Admin only)
app.put(
  '/api/admin/user/:userId',
  authenticate(async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'You do not have permission to update users' });
    }

    const { userId } = req.params;
    const { username, role } = req.body;

    try {
      const updatedUser = await prisma.user.update({
        where: { id: Number(userId) },
        data: { username, role },
      });
      res.status(200).json(updatedUser);
    } catch (err) {
      res.status(500).json({ error: 'Error updating user' });
    }
  })
);

// API: Delete User (Admin only)
app.delete(
  '/api/admin/user/:userId',
  authenticate(async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'You do not have permission to delete users' });
    }

    const { userId } = req.params;

    try {
      await prisma.user.delete({
        where: { id: Number(userId) },
      });
      res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Error deleting user' });
    }
  })
);


// Starting the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
