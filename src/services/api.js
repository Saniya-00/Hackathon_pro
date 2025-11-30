// API Base URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

// Helper function to get auth token
const getAuthToken = () => {
  return localStorage.getItem('token');
};

// ==================== AUTH API ====================

export const authAPI = {
  // Register new user
  register: async (userData) => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Registration failed');
      }

      return data;
    } catch (error) {
      throw error;
    }
  },

  // Login user
  login: async (credentials) => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Login failed');
      }

      // Save token to localStorage
      if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
      }

      return data;
    } catch (error) {
      throw error;
    }
  },

  // Logout user
  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },

  // Get current user from localStorage
  getCurrentUser: () => {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  },
};

// ==================== ACHIEVEMENTS API ====================

export const achievementsAPI = {
  // Get all achievements
  getAll: async () => {
    try {
      const token = getAuthToken();
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await fetch(`${API_BASE_URL}/achievements`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Failed to fetch achievements');
      }

      return data;
    } catch (error) {
      throw error;
    }
  },

  // Create new achievement
  create: async (achievementData) => {
    try {
      const token = getAuthToken();
      if (!token) {
        throw new Error('No authentication token found');
      }

      const formData = new FormData();
      formData.append('studentName', achievementData.studentName);
      formData.append('studentId', achievementData.studentId);
      formData.append('category', achievementData.category);
      formData.append('title', achievementData.title);
      formData.append('awardType', achievementData.awardType);
      
      if (achievementData.file) {
        formData.append('file', achievementData.file);
      }

      const response = await fetch(`${API_BASE_URL}/achievements`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Failed to create achievement');
      }

      return data;
    } catch (error) {
      throw error;
    }
  },

  // Verify achievement (Admin only)
  verify: async (achievementId) => {
    try {
      const token = getAuthToken();
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await fetch(`${API_BASE_URL}/achievements/${achievementId}/verify`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Failed to verify achievement');
      }

      return data;
    } catch (error) {
      throw error;
    }
  },

  // Delete achievement (Admin only)
  delete: async (achievementId) => {
    try {
      const token = getAuthToken();
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await fetch(`${API_BASE_URL}/achievements/${achievementId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Failed to delete achievement');
      }

      return data;
    } catch (error) {
      throw error;
    }
  },

  // Download achievement file
  downloadFile: async (achievementId, fileName) => {
    try {
      const token = getAuthToken();
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await fetch(`${API_BASE_URL}/achievements/${achievementId}/download`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to download file');
      }

      // Create blob and download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      throw error;
    }
  },

  // Export achievements as CSV
  exportCSV: async () => {
    try {
      const token = getAuthToken();
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await fetch(`${API_BASE_URL}/achievements/export/csv`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to export CSV');
      }

      // Create blob and download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'achievements.csv';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      throw error;
    }
  },
};