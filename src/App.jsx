import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Download, CheckCircle, Trash2, Upload, Sun, Moon, Palette, FileDown, MessageCircle, X, Send } from "lucide-react";

const themes = {
  red: {
    primary: "bg-red-600",
    primaryHover: "hover:bg-red-700",
    primaryText: "text-red-600",
    gradient: "from-red-500 to-red-700"
  },
  blue: {
    primary: "bg-blue-600",
    primaryHover: "hover:bg-blue-700",
    primaryText: "text-blue-600",
    gradient: "from-blue-500 to-blue-700"
  },
  purple: {
    primary: "bg-purple-600",
    primaryHover: "hover:bg-purple-700",
    primaryText: "text-purple-600",
    gradient: "from-purple-500 to-purple-700"
  },
  green: {
    primary: "bg-green-600",
    primaryHover: "hover:bg-green-700",
    primaryText: "text-green-600",
    gradient: "from-green-500 to-green-700"
  },
  orange: {
    primary: "bg-orange-600",
    primaryHover: "hover:bg-orange-700",
    primaryText: "text-orange-600",
    gradient: "from-orange-500 to-orange-700"
  }
};

export default function App() {
  const [page, setPage] = useState("login");
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ name: "", email: "", password: "", role: "student" });
  const [currentUser, setCurrentUser] = useState(null);
  const [achievements, setAchievements] = useState([]);
  const [notif, setNotif] = useState("");
  const [darkMode, setDarkMode] = useState(false);
  const [colorTheme, setColorTheme] = useState("red");
  const [showThemeMenu, setShowThemeMenu] = useState(false);
  const [showChatbot, setShowChatbot] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [isChatbotMinimized, setIsChatbotMinimized] = useState(false);

  const theme = themes[colorTheme];

  useEffect(() => {
    if (notif) {
      const timer = setTimeout(() => setNotif(""), 2500);
      return () => clearTimeout(timer);
    }
  }, [notif]);

  const validateForm = () => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
    const passRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/;
    if (!emailRegex.test(form.email)) return "Invalid email format!";
    if (!passRegex.test(form.password))
      return "Password must contain letters, numbers & a special symbol (min 6 chars)";
    return "";
  };

  const handleSignup = () => {
    const error = validateForm();
    if (error) return setNotif(error);
    if (users.find((u) => u.email === form.email))
      return setNotif("User already exists!");
    setUsers([...users, form]);
    setNotif("Signup successful! Please login.");
    setForm({ name: "", email: "", password: "", role: "student" });
    setPage("login");
  };

  const handleLogin = () => {
    const found = users.find(
      (u) => u.email === form.email && u.password === form.password
    );
    if (!found) return setNotif("Invalid email or password!");
    setCurrentUser(found);
    setNotif(`Welcome, ${found.name}!`);
    setPage("dashboard");
    
    // Show chatbot with welcome message after login
    setTimeout(() => {
      setShowChatbot(true);
      setChatMessages([{
        type: "bot",
        text: `Hi ${found.name}! 👋 I'm StuBuddy, your friendly assistant! How can I help you today?`,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    }, 1000);
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setPage("login");
    setNotif("Logged out successfully!");
    setShowChatbot(false);
    setChatMessages([]);
  };

  const handleAdd = (data) => {
    setAchievements([...achievements, { ...data, id: Date.now(), verified: false }]);
    setNotif("Achievement added successfully!");
  };

  const handleVerify = (id) => {
    setAchievements(
      achievements.map((a) => (a.id === id ? { ...a, verified: true } : a))
    );
    setNotif("Achievement verified!");
  };

  const handleDelete = (id) => {
    setAchievements(achievements.filter((a) => a.id !== id));
    setNotif("Deleted successfully!");
  };

  const handleExportCSV = () => {
    const headers = "ID,Student Name,Student ID,Category,Title,Award Type,Verified,File Name\n";
    const csv = headers + achievements
      .map((a) =>
        [a.id, a.studentName, a.studentId, a.category, a.title, a.awardType, a.verified, a.fileName || 'No file'].join(",")
      )
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "achievements.csv";
    link.click();
    setNotif("CSV exported successfully!");
  };

  const handleDownloadFile = (achievement) => {
    if (!achievement.file) {
      setNotif("No file attached to this achievement!");
      return;
    }
    
    const link = document.createElement("a");
    link.href = achievement.file;
    link.download = achievement.fileName;
    link.click();
    setNotif(`Downloading ${achievement.fileName}...`);
  };

  const handleSendMessage = () => {
    if (!chatInput.trim()) return;

    const userMessage = {
      type: "user",
      text: chatInput,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setChatMessages([...chatMessages, userMessage]);
    setChatInput("");

    // Simulate bot response
    setTimeout(() => {
      const botResponse = getBotResponse(chatInput.toLowerCase());
      setChatMessages(prev => [...prev, {
        type: "bot",
        text: botResponse,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    }, 1000);
  };

  const getBotResponse = (message) => {
    if (message.includes("hello") || message.includes("hi") || message.includes("hey")) {
      return "Hello! 😊 How can I assist you today?";
    } else if (message.includes("upload") || message.includes("submit")) {
      return "To upload an achievement, go to your dashboard and fill in the form with your achievement details. Don't forget to attach your certificate or proof document! 📄";
    } else if (message.includes("verify") || message.includes("verification")) {
      return "Once you submit an achievement, our admin team will review and verify it. You'll see a green checkmark ✓ once it's verified! ⏳";
    } else if (message.includes("category") || message.includes("categories")) {
      return "We track various categories: Sports & Athletics 🏆, Arts & Culture 🎨, Technology & Innovation 💻, Social & Community 🤝, Academic Excellence 🎓, and more! Check the About Us page for details.";
    } else if (message.includes("download") || message.includes("export")) {
      return "Admins can download individual achievement files or export all data as CSV. Students can view their submitted achievements in the dashboard! 📊";
    } else if (message.includes("help") || message.includes("support")) {
      return "I'm here to help! You can ask me about:\n• How to upload achievements\n• Verification process\n• Activity categories\n• Using the dashboard\n• Exporting data\nJust ask away! 💬";
    } else if (message.includes("theme") || message.includes("color")) {
      return "You can customize your experience! Click the palette icon 🎨 in the navbar to choose from 5 color themes, and toggle dark/light mode with the sun/moon icon! 🌙☀️";
    } else if (message.includes("thank")) {
      return "You're welcome! Happy to help! 😊 Feel free to ask if you have more questions!";
    } else if (message.includes("bye") || message.includes("goodbye")) {
      return "Goodbye! Have a great day! 👋 Feel free to chat with me anytime!";
    } else {
      return "I'm StuBuddy! 🤖 I can help you with uploading achievements, understanding the verification process, exploring activity categories, and navigating the platform. What would you like to know?";
    }
  };

  return (
    <div className={`min-h-screen flex flex-col transition-colors duration-300 ${
      darkMode ? "bg-gray-900" : "bg-gradient-to-br from-gray-50 to-gray-100"
    }`}>
      {/* NAVBAR */}
      <header className={`${theme.primary} text-white py-4 shadow-lg transition-all duration-300`}>
        <div className="max-w-6xl mx-auto px-6 flex justify-between items-center">
          <motion.div 
            className="text-2xl font-bold tracking-wide"
            whileHover={{ scale: 1.05 }}
          >
            STUTRACK
          </motion.div>
          <nav className="flex gap-3 items-center text-sm font-medium">
            <button 
              onClick={() => setPage("dashboard")} 
              className="text-white hover:text-yellow-300 transition-colors px-2 py-1"
              style={{ background: 'none', border: 'none' }}
            >
              Dashboard
            </button>
            <button 
              onClick={() => setPage("about")} 
              className="text-white hover:text-yellow-300 transition-colors px-2 py-1"
              style={{ background: 'none', border: 'none' }}
            >
              About Us
            </button>
            <button 
              onClick={() => setPage("login")} 
              className="text-white hover:text-yellow-300 transition-colors px-2 py-1"
              style={{ background: 'none', border: 'none' }}
            >
              Login
            </button>
            <button 
              onClick={() => setPage("signup")} 
              className="text-white hover:text-yellow-300 transition-colors px-2 py-1"
              style={{ background: 'none', border: 'none' }}
            >
              Signup
            </button>
            {currentUser && (
              <button 
                onClick={handleLogout} 
                className="text-white hover:text-yellow-300 transition-colors px-2 py-1"
                style={{ background: 'none', border: 'none' }}
              >
                Logout
              </button>
            )}
            
            {/* Theme Controls */}
            <div className="flex gap-2 ml-2 pl-2" style={{ borderLeft: '1px solid rgba(255,255,255,0.3)' }}>
              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => setDarkMode(!darkMode)}
                className="p-2 rounded-lg transition-colors"
                style={{ background: 'rgba(255,255,255,0.2)', border: 'none' }}
                title={darkMode ? "Light Mode" : "Dark Mode"}
              >
                {darkMode ? <Sun size={18} /> : <Moon size={18} />}
              </motion.button>
              
              <div className="relative">
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={() => setShowThemeMenu(!showThemeMenu)}
                  className="p-2 rounded-lg transition-colors"
                  style={{ background: 'rgba(255,255,255,0.2)', border: 'none' }}
                  title="Change Theme"
                >
                  <Palette size={18} />
                </motion.button>
                
                <AnimatePresence>
                  {showThemeMenu && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className={`absolute right-0 mt-2 p-3 rounded-lg shadow-xl ${
                        darkMode ? "bg-gray-800" : "bg-white"
                      } z-50`}
                    >
                      <div className="flex gap-2">
                        {Object.keys(themes).map((themeName) => (
                          <motion.button
                            key={themeName}
                            whileHover={{ scale: 1.2 }}
                            whileTap={{ scale: 0.9 }}
                            onClick={() => {
                              setColorTheme(themeName);
                              setShowThemeMenu(false);
                            }}
                            className={`w-8 h-8 rounded-full ${themes[themeName].primary} ${
                              colorTheme === themeName ? "ring-4 ring-offset-2 ring-yellow-400" : ""
                            }`}
                            title={themeName.charAt(0).toUpperCase() + themeName.slice(1)}
                          />
                        ))}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </nav>
        </div>
      </header>

      {/* NOTIFICATION - CENTERED */}
      <AnimatePresence>
        {notif && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            className={`fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 ${theme.primary} text-white px-8 py-4 rounded-xl shadow-2xl z-50 text-center min-w-[300px]`}
            style={{ transform: 'translate(-50%, -50%)' }}
          >
            {notif}
          </motion.div>
        )}
      </AnimatePresence>

      <main className="flex-1 max-w-6xl mx-auto px-4 py-10">
        <AnimatePresence mode="wait">
          {page === "login" && (
            <motion.div
              key="login"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className={`max-w-md mx-auto p-8 rounded-2xl shadow-2xl ${
                darkMode ? "bg-gray-800 text-white" : "bg-white"
              }`}
            >
              <h2 className={`text-3xl font-bold text-center mb-6 bg-gradient-to-r ${theme.gradient} bg-clip-text text-transparent`}>
                Login
              </h2>
              <input
                type="email"
                placeholder="Email"
                className={`w-full border-2 p-3 mb-4 rounded-lg focus:outline-none focus:border-${colorTheme}-500 transition-colors ${
                  darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
                }`}
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
              />
              <input
                type="password"
                placeholder="Password"
                className={`w-full border-2 p-3 mb-4 rounded-lg focus:outline-none focus:border-${colorTheme}-500 transition-colors ${
                  darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
                }`}
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
              />
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleLogin}
                className={`w-full ${theme.primary} ${theme.primaryHover} text-white py-3 rounded-lg font-semibold shadow-lg transition-all`}
              >
                Login
              </motion.button>
              <p className={`text-center text-sm mt-4 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>
                No account?{" "}
                <button onClick={() => setPage("signup")} className={`${theme.primaryText} font-semibold hover:underline`}>
                  Sign up
                </button>
              </p>
            </motion.div>
          )}

          {page === "signup" && (
            <motion.div
              key="signup"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className={`max-w-md mx-auto p-8 rounded-2xl shadow-2xl ${
                darkMode ? "bg-gray-800 text-white" : "bg-white"
              }`}
            >
              <h2 className={`text-3xl font-bold text-center mb-6 bg-gradient-to-r ${theme.gradient} bg-clip-text text-transparent`}>
                Sign Up
              </h2>
              <input
                type="text"
                placeholder="Full Name"
                className={`w-full border-2 p-3 mb-4 rounded-lg focus:outline-none focus:border-${colorTheme}-500 transition-colors ${
                  darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
                }`}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
              <input
                type="email"
                placeholder="Email"
                className={`w-full border-2 p-3 mb-4 rounded-lg focus:outline-none focus:border-${colorTheme}-500 transition-colors ${
                  darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
                }`}
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
              />
              <input
                type="password"
                placeholder="Password"
                className={`w-full border-2 p-3 mb-4 rounded-lg focus:outline-none focus:border-${colorTheme}-500 transition-colors ${
                  darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
                }`}
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
              />
              <select
                className={`w-full border-2 p-3 mb-4 rounded-lg focus:outline-none focus:border-${colorTheme}-500 transition-colors ${
                  darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
                }`}
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value })}
              >
                <option value="student">Student</option>
                <option value="admin">Admin</option>
              </select>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleSignup}
                className={`w-full ${theme.primary} ${theme.primaryHover} text-white py-3 rounded-lg font-semibold shadow-lg transition-all`}
              >
                Create Account
              </motion.button>
              <p className={`text-center text-sm mt-4 ${darkMode ? "text-gray-400" : "text-gray-600"}`}>
                Already have an account?{" "}
                <button onClick={() => setPage("login")} className={`${theme.primaryText} font-semibold hover:underline`}>
                  Login
                </button>
              </p>
            </motion.div>
          )}

          {page === "dashboard" && currentUser && (
            <motion.div
              key="dashboard"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
              className={`p-8 rounded-2xl shadow-2xl ${
                darkMode ? "bg-gray-800 text-white" : "bg-white"
              }`}
            >
              <div className="flex justify-between items-center mb-6">
                <h2 className={`text-3xl font-bold bg-gradient-to-r ${theme.gradient} bg-clip-text text-transparent`}>
                  {currentUser.role === "admin" ? "Admin Dashboard" : "Student Dashboard"}
                </h2>
                {currentUser.role === "admin" && (
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={handleExportCSV}
                    className="bg-green-500 hover:bg-green-600 text-white flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold shadow-lg transition-all"
                  >
                    <Download size={16} /> Export CSV
                  </motion.button>
                )}
              </div>

              {currentUser.role === "student" ? (
                <StudentSection onAdd={handleAdd} darkMode={darkMode} theme={theme} />
              ) : (
                <AdminSection
                  achievements={achievements}
                  handleVerify={handleVerify}
                  handleDelete={handleDelete}
                  handleDownloadFile={handleDownloadFile}
                  darkMode={darkMode}
                />
              )}
            </motion.div>
          )}

          {page === "about" && (
            <motion.div
              key="about"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
              className={`p-8 rounded-2xl shadow-2xl ${
                darkMode ? "bg-gray-800 text-white" : "bg-white"
              }`}
            >
              <h2 className={`text-4xl font-bold text-center mb-8 bg-gradient-to-r ${theme.gradient} bg-clip-text text-transparent`}>
                About StuTrack
              </h2>
              
              <div className="mb-8">
                <p className={`text-lg mb-4 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                  StuTrack is a comprehensive platform designed to help students track, manage, and showcase their extracurricular achievements. 
                  We believe that every achievement matters, and our mission is to make it easy for students to document their journey beyond academics.
                </p>
              </div>

              <h3 className={`text-2xl font-bold mb-4 ${darkMode ? "text-gray-200" : "text-gray-800"}`}>
                Extracurricular Activities We Track
              </h3>

              <div className="grid md:grid-cols-2 gap-6 mb-8">
                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className={`p-6 rounded-xl ${
                    darkMode ? "bg-gray-700/50" : "bg-gradient-to-br from-blue-50 to-blue-100"
                  } border-2 ${darkMode ? "border-gray-600" : "border-blue-200"}`}
                >
                  <h4 className={`text-xl font-semibold mb-3 ${theme.primaryText}`}>🏆 Sports & Athletics</h4>
                  <ul className={`space-y-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                    <li>• Inter-school/college competitions</li>
                    <li>• State & national level tournaments</li>
                    <li>• Team championships</li>
                    <li>• Individual medals and trophies</li>
                    <li>• Sports participation certificates</li>
                  </ul>
                </motion.div>

                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className={`p-6 rounded-xl ${
                    darkMode ? "bg-gray-700/50" : "bg-gradient-to-br from-purple-50 to-purple-100"
                  } border-2 ${darkMode ? "border-gray-600" : "border-purple-200"}`}
                >
                  <h4 className={`text-xl font-semibold mb-3 ${theme.primaryText}`}>🎨 Arts & Culture</h4>
                  <ul className={`space-y-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                    <li>• Dance competitions and performances</li>
                    <li>• Music concerts and recitals</li>
                    <li>• Drama and theater awards</li>
                    <li>• Art exhibitions and contests</li>
                    <li>• Creative writing competitions</li>
                  </ul>
                </motion.div>

                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className={`p-6 rounded-xl ${
                    darkMode ? "bg-gray-700/50" : "bg-gradient-to-br from-green-50 to-green-100"
                  } border-2 ${darkMode ? "border-gray-600" : "border-green-200"}`}
                >
                  <h4 className={`text-xl font-semibold mb-3 ${theme.primaryText}`}>💻 Technology & Innovation</h4>
                  <ul className={`space-y-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                    <li>• Hackathons and coding competitions</li>
                    <li>• Science fairs and exhibitions</li>
                    <li>• Robotics competitions</li>
                    <li>• Tech conferences and workshops</li>
                    <li>• Project showcases and demos</li>
                  </ul>
                </motion.div>

                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className={`p-6 rounded-xl ${
                    darkMode ? "bg-gray-700/50" : "bg-gradient-to-br from-orange-50 to-orange-100"
                  } border-2 ${darkMode ? "border-gray-600" : "border-orange-200"}`}
                >
                  <h4 className={`text-xl font-semibold mb-3 ${theme.primaryText}`}>🤝 Social & Community</h4>
                  <ul className={`space-y-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                    <li>• Volunteer work and community service</li>
                    <li>• Leadership positions in clubs</li>
                    <li>• Social awareness campaigns</li>
                    <li>• NGO collaborations</li>
                    <li>• Environmental initiatives</li>
                  </ul>
                </motion.div>

                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className={`p-6 rounded-xl ${
                    darkMode ? "bg-gray-700/50" : "bg-gradient-to-br from-red-50 to-red-100"
                  } border-2 ${darkMode ? "border-gray-600" : "border-red-200"}`}
                >
                  <h4 className={`text-xl font-semibold mb-3 ${theme.primaryText}`}>🎓 Academic Excellence</h4>
                  <ul className={`space-y-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                    <li>• Olympiad medals and certificates</li>
                    <li>• Quiz competitions</li>
                    <li>• Debate and public speaking awards</li>
                    <li>• Research paper publications</li>
                    <li>• Academic scholarships</li>
                  </ul>
                </motion.div>

                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className={`p-6 rounded-xl ${
                    darkMode ? "bg-gray-700/50" : "bg-gradient-to-br from-yellow-50 to-yellow-100"
                  } border-2 ${darkMode ? "border-gray-600" : "border-yellow-200"}`}
                >
                  <h4 className={`text-xl font-semibold mb-3 ${theme.primaryText}`}>🌟 Other Achievements</h4>
                  <ul className={`space-y-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                    <li>• Certifications and courses</li>
                    <li>• Internships and work experience</li>
                    <li>• Model UN and conferences</li>
                    <li>• Entrepreneurship ventures</li>
                    <li>• Special recognitions and honors</li>
                  </ul>
                </motion.div>
              </div>

              <div className={`p-6 rounded-xl ${
                darkMode ? "bg-gray-700/50 border-gray-600" : "bg-gradient-to-r from-indigo-50 to-purple-50 border-indigo-200"
              } border-2`}>
                <h3 className={`text-xl font-bold mb-3 ${darkMode ? "text-gray-200" : "text-gray-800"}`}>
                  Why Track Your Achievements?
                </h3>
                <ul className={`space-y-2 ${darkMode ? "text-gray-300" : "text-gray-700"}`}>
                  <li>✅ Build a comprehensive portfolio for college applications</li>
                  <li>✅ Keep all certificates and documents organized in one place</li>
                  <li>✅ Share your achievements with mentors and institutions</li>
                  <li>✅ Track your growth and progress over time</li>
                  <li>✅ Get verified achievements from administrators</li>
                </ul>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className={`text-sm text-center py-4 transition-colors ${
        darkMode ? "bg-gray-800 text-gray-400" : "bg-gray-200 text-gray-700"
      }`}>
        © 2025 StuTrack. Designed with ❤️ using React + Tailwind + Framer Motion
      </footer>

      {/* CHATBOT - StuBuddy */}
      {currentUser && (
        <>
          <AnimatePresence>
            {showChatbot && !isChatbotMinimized && (
              <motion.div
                initial={{ opacity: 0, y: 100, scale: 0.8 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 100, scale: 0.8 }}
                className={`fixed bottom-24 right-6 w-96 h-[500px] rounded-2xl shadow-2xl z-50 flex flex-col ${
                  darkMode ? "bg-gray-800 border-2 border-gray-700" : "bg-white border-2 border-gray-200"
                }`}
              >
                {/* Chatbot Header */}
                <div className={`${theme.primary} text-white p-4 rounded-t-2xl flex items-center justify-between`}>
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-white rounded-full flex items-center justify-center text-2xl">
                      🤖
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">StuBuddy</h3>
                      <p className="text-xs opacity-90">Your AI Assistant</p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <motion.button
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                      onClick={() => setIsChatbotMinimized(true)}
                      className="text-white hover:bg-white/20 p-1 rounded"
                      style={{ background: 'none', border: 'none' }}
                    >
                      ─
                    </motion.button>
                    <motion.button
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                      onClick={() => setShowChatbot(false)}
                      className="text-white hover:bg-white/20 p-1 rounded"
                      style={{ background: 'none', border: 'none' }}
                    >
                      <X size={20} />
                    </motion.button>
                  </div>
                </div>

                {/* Chat Messages */}
                <div className={`flex-1 overflow-y-auto p-4 space-y-3 ${
                  darkMode ? "bg-gray-900" : "bg-gray-50"
                }`}>
                  {chatMessages.map((msg, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={`flex ${msg.type === "user" ? "justify-end" : "justify-start"}`}
                    >
                      <div className={`max-w-[80%] ${
                        msg.type === "user" 
                          ? `${theme.primary} text-white` 
                          : darkMode ? "bg-gray-700 text-white" : "bg-white text-gray-800 border border-gray-200"
                      } p-3 rounded-2xl shadow-md`}>
                        <p className="text-sm whitespace-pre-line">{msg.text}</p>
                        <p className={`text-xs mt-1 ${
                          msg.type === "user" ? "text-white/70" : darkMode ? "text-gray-400" : "text-gray-500"
                        }`}>
                          {msg.time}
                        </p>
                      </div>
                    </motion.div>
                  ))}
                </div>

                {/* Chat Input */}
                <div className={`p-4 border-t-2 ${darkMode ? "border-gray-700" : "border-gray-200"}`}>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Type your message..."
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      onKeyPress={(e) => e.key === "Enter" && handleSendMessage()}
                      className={`flex-1 border-2 p-3 rounded-lg focus:outline-none ${
                        darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
                      }`}
                    />
                    <motion.button
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      onClick={handleSendMessage}
                      className={`${theme.primary} ${theme.primaryHover} text-white p-3 rounded-lg`}
                    >
                      <Send size={20} />
                    </motion.button>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Chatbot Toggle Button */}
          <motion.button
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.9 }}
            onClick={() => {
              setShowChatbot(!showChatbot);
              setIsChatbotMinimized(false);
            }}
            className={`fixed bottom-6 right-6 w-16 h-16 ${theme.primary} ${theme.primaryHover} text-white rounded-full shadow-2xl z-50 flex items-center justify-center`}
          >
            {showChatbot && !isChatbotMinimized ? (
              <X size={28} />
            ) : (
              <div className="relative">
                <MessageCircle size={28} />
                {chatMessages.length > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 bg-green-500 rounded-full border-2 border-white"></span>
                )}
              </div>
            )}
          </motion.button>
        </>
      )}
    </div>
  );
}

function StudentSection({ onAdd, darkMode, theme }) {
  const [data, setData] = useState({
    studentName: "",
    studentId: "",
    category: "",
    title: "",
    awardType: "",
    file: null,
    fileName: ""
  });

  const handleFile = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setData({ ...data, file: reader.result, fileName: file.name });
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = () => {
    if (!data.studentName || !data.studentId || !data.title) {
      alert("Please fill all required fields!");
      return;
    }
    onAdd(data);
    setData({
      studentName: "",
      studentId: "",
      category: "",
      title: "",
      awardType: "",
      file: null,
      fileName: ""
    });
  };

  return (
    <div>
      <h3 className={`text-2xl font-semibold mb-4 ${darkMode ? "text-gray-200" : "text-gray-700"}`}>
        Submit Achievement
      </h3>
      <div className="grid md:grid-cols-2 gap-4">
        <input
          className={`border-2 p-3 rounded-lg focus:outline-none transition-colors ${
            darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
          }`}
          placeholder="Student Name *"
          value={data.studentName}
          onChange={(e) => setData({ ...data, studentName: e.target.value })}
        />
        <input
          className={`border-2 p-3 rounded-lg focus:outline-none transition-colors ${
            darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
          }`}
          placeholder="Student ID *"
          value={data.studentId}
          onChange={(e) => setData({ ...data, studentId: e.target.value })}
        />
        <input
          className={`border-2 p-3 rounded-lg focus:outline-none transition-colors ${
            darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
          }`}
          placeholder="Category"
          value={data.category}
          onChange={(e) => setData({ ...data, category: e.target.value })}
        />
        <input
          className={`border-2 p-3 rounded-lg focus:outline-none transition-colors ${
            darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
          }`}
          placeholder="Title *"
          value={data.title}
          onChange={(e) => setData({ ...data, title: e.target.value })}
        />
        <input
          className={`border-2 p-3 rounded-lg focus:outline-none transition-colors ${
            darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
          }`}
          placeholder="Award Type"
          value={data.awardType}
          onChange={(e) => setData({ ...data, awardType: e.target.value })}
        />
        <div className="relative">
          <input
            type="file"
            accept="image/*,.pdf,.doc,.docx"
            onChange={handleFile}
            className={`border-2 p-3 rounded-lg transition-colors w-full ${
              darkMode ? "bg-gray-700 border-gray-600 text-white" : "bg-gray-50 border-gray-300"
            }`}
          />
          {data.fileName && (
            <span className={`text-xs mt-1 block ${darkMode ? "text-green-400" : "text-green-600"}`}>
              ✓ {data.fileName}
            </span>
          )}
        </div>
      </div>
      <motion.button
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        onClick={handleSubmit}
        className={`mt-6 ${theme.primary} ${theme.primaryHover} text-white px-6 py-3 rounded-lg flex items-center gap-2 font-semibold shadow-lg transition-all`}
      >
        <Upload size={16} /> Submit Achievement
      </motion.button>
    </div>
  );
}

function AdminSection({ achievements, handleVerify, handleDelete, handleDownloadFile, darkMode }) {
  return (
    <div>
      <h3 className={`text-2xl font-semibold mb-4 ${darkMode ? "text-gray-200" : "text-gray-700"}`}>
        All Submissions
      </h3>
      {achievements.length === 0 ? (
        <p className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-500"}`}>
          No submissions yet.
        </p>
      ) : (
        <div className="space-y-3">
          {achievements.map((a) => (
            <motion.div
              key={a.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className={`border-2 p-4 rounded-lg flex justify-between items-center transition-colors ${
                darkMode ? "border-gray-700 bg-gray-700/50" : "border-gray-200 bg-gray-50"
              }`}
            >
              <div className="flex-1">
                <div className={`font-semibold text-lg ${darkMode ? "text-white" : "text-gray-800"}`}>
                  {a.title}
                </div>
                <div className={`text-sm ${darkMode ? "text-gray-400" : "text-gray-500"}`}>
                  {a.studentName} ({a.studentId}) • {a.category} • {a.awardType}
                  {a.verified && <span className="ml-2 text-green-500 font-semibold">✓ Verified</span>}
                </div>
                {a.fileName && (
                  <div className={`text-xs mt-1 ${darkMode ? "text-blue-400" : "text-blue-600"}`}>
                    📎 {a.fileName}
                  </div>
                )}
              </div>
              <div className="flex gap-2">
                {a.file && (
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={() => handleDownloadFile(a)}
                    className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center gap-1 font-semibold shadow-md transition-all"
                  >
                    <FileDown size={16} /> Download
                  </motion.button>
                )}
                {!a.verified && (
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={() => handleVerify(a.id)}
                    className="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg flex items-center gap-1 font-semibold shadow-md transition-all"
                  >
                    <CheckCircle size={16} /> Verify
                  </motion.button>
                )}
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => handleDelete(a.id)}
                  className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg flex items-center gap-1 font-semibold shadow-md transition-all"
                >
                  <Trash2 size={16} /> Delete
                </motion.button>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}