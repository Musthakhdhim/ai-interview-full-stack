import axios from 'axios';

const axiosClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api/v1',
  headers: { 'Content-Type': 'application/json' },
});

// Attach token if present
axiosClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Handle 401 - logout
axiosClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Do NOT use window.location.href inside a React app – it forces full reload.
      // Instead, dispatch logout action and rely on React Router.
      // For now, just return reject and let the page handle it.
      localStorage.removeItem('accessToken');
      localStorage.removeItem('user');
      // Do NOT redirect here – this will be caught by your component.
    }
    return Promise.reject(error);
  }
);

export default axiosClient;