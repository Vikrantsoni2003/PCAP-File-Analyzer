import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import pcapParser from 'pcap-parser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// MongoDB Connection - with fallback for local operation
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/pcap_analyzer';
let isMongoConnected = false;
let db = null;
let gfs = null;
let Feedback = null;
let Report = null;

// Try to connect to MongoDB but don't block app startup if it fails
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    isMongoConnected = true;
    db = mongoose.connection;
    
    // Set up models only if MongoDB is connected
    setupMongoModels();
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    console.log('Running in local mode without MongoDB persistence');
  });

// Setup MongoDB models and GridFS
function setupMongoModels() {
  // Define Schemas
  const feedbackSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  });

  const reportSchema = new mongoose.Schema({
    userId: { type: String, default: 'anonymous' },
    reportName: { type: String, required: true },
    reportType: { type: String, enum: ['PDF', 'JSON', 'CSV'], required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    createdAt: { type: Date, default: Date.now }
  });

  // Create models
  Feedback = mongoose.model('Feedback', feedbackSchema);
  Report = mongoose.model('Report', reportSchema);

  // Set up GridFS for file storage
  try {
    const { GridFSBucket } = mongoose.mongo;
    gfs = new GridFSBucket(db.db, {
      bucketName: 'uploads'
    });
    console.log('GridFS initialized');
  } catch (error) {
    console.error('Error initializing GridFS:', error);
  }
}

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function(req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: function(req, file, cb) {
    if (file.originalname.endsWith('.pcap')) {
      cb(null, true);
    } else {
      cb(new Error('Only .pcap files are allowed'));
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Routes

// Upload and analyze PCAP file - Using the existing PCAP parsing logic
app.post('/api/upload', upload.single('pcapFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    let fileId = null;
    
    // Store file in GridFS if MongoDB is connected
    if (isMongoConnected && gfs) {
      try {
        const fileStream = fs.createReadStream(filePath);
        const uploadStream = gfs.openUploadStream(req.file.originalname, {
          metadata: {
            mimetype: req.file.mimetype,
            uploadDate: new Date()
          }
        });
        
        fileStream.pipe(uploadStream);
        fileId = uploadStream.id;
        console.log('File stored in GridFS with ID:', fileId);
      } catch (error) {
        console.error('Error storing file in GridFS:', error);
        // Continue with local file processing
      }
    }
    
    // Process the PCAP file using the existing logic from app.js
    let totalPackets = 0;
    const packetDetails = [];
    const threats = [];
    const connectionCounts = {}; // For detecting port scans and DDoS

    try {
      const parser = pcapParser.parse(fs.createReadStream(filePath));

      parser.on("packet", (packet) => {
        totalPackets++;

        try {
          const ethertype = packet.data.readUInt16BE(12);

          if (ethertype === 0x0800) {
            // IPv4
            const srcIP = `${packet.data[26]}.${packet.data[27]}.${packet.data[28]}.${packet.data[29]}`;
            const dstIP = `${packet.data[30]}.${packet.data[31]}.${packet.data[32]}.${packet.data[33]}`;

            const protocol = packet.data[23];
            let protoName = "";
            if (protocol === 6) protoName = "TCP";
            else if (protocol === 17) protoName = "UDP";
            else if (protocol === 1) protoName = "ICMP";
            else protoName = `Unknown (${protocol})`;

            const packetLength = packet.data.length || packet.header?.orig_len || 0;

            packetDetails.push({
              srcIP,
              dstIP,
              protocol: protoName,
              packetSize: packetLength,
            });

            // Track connections for threat detection
            const connectionKey = `${srcIP}->${dstIP}`;
            connectionCounts[connectionKey] = (connectionCounts[connectionKey] || 0) + 1;
          }
        } catch (packetError) {
          console.error('Error processing packet:', packetError);
          // Continue with next packet
        }
      });

      parser.on("end", () => {
        // Threat Detection Logic
        for (const [connection, count] of Object.entries(connectionCounts)) {
          if (count > 100) {
            threats.push({
              type: "Potential DDoS",
              description: `High traffic detected on connection ${connection} with ${count} packets.`,
            });
          }
        }

        // Simple Port Scan Detection
        const portScanSources = {};
        packetDetails.forEach((packet) => {
          const key = packet.srcIP;
          portScanSources[key] = portScanSources[key] || new Set();
          portScanSources[key].add(packet.dstIP);
        });

        for (const [srcIP, dstIPs] of Object.entries(portScanSources)) {
          if (dstIPs.size > 20) {
            threats.push({
              type: "Potential Port Scan",
              description: `Source IP ${srcIP} connected to ${dstIPs.size} unique destinations.`,
            });
          }
        }

        const analysisResult = {
          totalPackets,
          packetDetails,
          threats,
          timestamp: new Date().toISOString()
        };

        // Schedule file deletion after analysis (5 minutes)
        setTimeout(() => {
          // Delete from GridFS if available
          if (isMongoConnected && gfs && fileId) {
            try {
              gfs.delete(fileId, (err) => {
                if (err) console.error('Error deleting file from GridFS:', err);
                else console.log(`File ${fileId} deleted from GridFS`);
              });
            } catch (error) {
              console.error('Error deleting file from GridFS:', error);
            }
          }
          
          // Delete local temp file
          if (fs.existsSync(filePath)) {
            fs.unlink(filePath, (err) => {
              if (err) console.error('Error deleting temp file:', err);
              else console.log(`Temp file ${filePath} deleted`);
            });
          }
        }, 5 * 60 * 1000); // 5 minutes

        res.json(analysisResult);
      });

      parser.on("error", (err) => {
        console.error("PCAP parsing error:", err);
        res.status(500).json({ error: "Failed to parse PCAP file." });
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      });
    } catch (err) {
      console.error("Error handling file:", err);
      res.status(500).json({ error: "An error occurred during file processing." });
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Submit feedback - with fallback for local operation
app.post('/api/feedback', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // If MongoDB is connected, save to database
    if (isMongoConnected && Feedback) {
      try {
        const feedback = new Feedback({
          name,
          email,
          message
        });
        
        await feedback.save();
        console.log('Feedback saved to MongoDB');
      } catch (error) {
        console.error('Error saving feedback to MongoDB:', error);
        // Continue with local operation
      }
    } else {
      // Local operation - log feedback to console
      console.log('Feedback received (local mode):', { name, email, message });
    }
    
    res.status(201).json({ message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Save report - with fallback for local operation
app.post('/api/reports', async (req, res) => {
  try {
    const { reportName, reportType, data, userId } = req.body;
    
    if (!reportName || !reportType || !data) {
      return res.status(400).json({ error: 'Report name, type, and data are required' });
    }
    
    let reportId = 'local_' + Date.now();
    
    // If MongoDB is connected, save to database
    if (isMongoConnected && Report) {
      try {
        const report = new Report({
          userId: userId || 'anonymous',
          reportName,
          reportType,
          data
        });
        
        const savedReport = await report.save();
        reportId = savedReport._id.toString();
        console.log('Report saved to MongoDB with ID:', reportId);
      } catch (error) {
        console.error('Error saving report to MongoDB:', error);
        // Continue with local operation
      }
    } else {
      // Local operation - save report to file
      const reportsDir = path.join(__dirname, 'reports');
      if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
      }
      
      const reportData = {
        _id: reportId,
        userId: userId || 'anonymous',
        reportName,
        reportType,
        data,
        createdAt: new Date().toISOString()
      };
      
      const reportPath = path.join(reportsDir, `${reportId}.json`);
      fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2));
      console.log('Report saved locally to:', reportPath);
    }
    
    res.status(201).json({ 
      message: 'Report saved successfully',
      reportId
    });
  } catch (error) {
    console.error('Report save error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user reports - with fallback for local operation
app.get('/api/reports/:userId', async (req, res) => {
  try {
    const userId = req.params.userId || 'anonymous';
    let reports = [];
    
    // If MongoDB is connected, get reports from database
    if (isMongoConnected && Report) {
      try {
        reports = await Report.find({ userId }).sort({ createdAt: -1 });
        console.log(`Found ${reports.length} reports in MongoDB for user ${userId}`);
      } catch (error) {
        console.error('Error getting reports from MongoDB:', error);
        // Continue with local operation
      }
    }
    
    // If no reports found in MongoDB or MongoDB is not connected, check local files
    if (reports.length === 0) {
      const reportsDir = path.join(__dirname, 'reports');
      if (fs.existsSync(reportsDir)) {
        const files = fs.readdirSync(reportsDir);
        for (const file of files) {
          if (file.endsWith('.json')) {
            try {
              const reportData = JSON.parse(fs.readFileSync(path.join(reportsDir, file), 'utf8'));
              if (reportData.userId === userId) {
                reports.push(reportData);
              }
            } catch (error) {
              console.error('Error reading local report file:', error);
            }
          }
        }
        reports.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        console.log(`Found ${reports.length} reports locally for user ${userId}`);
      }
    }
    
    res.json(reports);
  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get a specific report - with fallback for local operation
app.get('/api/reports/view/:reportId', async (req, res) => {
  try {
    const reportId = req.params.reportId;
    let report = null;
    
    // If MongoDB is connected, get report from database
    if (isMongoConnected && Report) {
      try {
        report = await Report.findById(reportId);
        if (report) {
          console.log('Report found in MongoDB:', reportId);
        }
      } catch (error) {
        console.error('Error getting report from MongoDB:', error);
        // Continue with local operation
      }
    }
    
    // If report not found in MongoDB or MongoDB is not connected, check local files
    if (!report) {
      const reportPath = path.join(__dirname, 'reports', `${reportId}.json`);
      if (fs.existsSync(reportPath)) {
        try {
          report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
          console.log('Report found locally:', reportId);
        } catch (error) {
          console.error('Error reading local report file:', error);
        }
      }
    }
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    res.json(report);
  } catch (error) {
    console.error('Get report error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete a report - with fallback for local operation
app.delete('/api/reports/:reportId', async (req, res) => {
  try {
    const reportId = req.params.reportId;
    let deleted = false;
    
    // If MongoDB is connected, delete report from database
    if (isMongoConnected && Report) {
      try {
        const result = await Report.findByIdAndDelete(reportId);
        if (result) {
          deleted = true;
          console.log('Report deleted from MongoDB:', reportId);
        }
      } catch (error) {
        console.error('Error deleting report from MongoDB:', error);
        // Continue with local operation
      }
    }
    
    // If report not deleted from MongoDB or MongoDB is not connected, check local files
    if (!deleted) {
      const reportPath = path.join(__dirname, 'reports', `${reportId}.json`);
      if (fs.existsSync(reportPath)) {
        fs.unlinkSync(reportPath);
        deleted = true;
        console.log('Report deleted locally:', reportId);
      }
    }
    
    if (!deleted) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    res.json({ message: 'Report deleted successfully' });
  } catch (error) {
    console.error('Delete report error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});

console.log('PCAP Analyzer backend initialized');