import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import axiosClient from '../../api/axiosClient';
import API from '../../api/endpoints';

const getErrorMessage = (error) => {
  if (!error.response) return 'Network error: Unable to connect to server';
  const { data } = error.response;
  if (data) {
    if (Array.isArray(data.data) && data.data.length > 0) return data.data.join(', ');
    if (data.message) return data.message;
  }
  return 'An unexpected error occurred';
};

// ---------- Thunks ----------
export const register = createAsyncThunk(
  'auth/register',
  async (userData, { rejectWithValue }) => {
    try {
      const response = await axiosClient.post(API.AUTH.REGISTER, userData);
      return response.data;
    } catch (error) {
      return rejectWithValue(getErrorMessage(error));
    }
  }
);

export const verifyOtp = createAsyncThunk(
  'auth/verifyOtp',
  async ({ email, otp }, { rejectWithValue }) => {
    try {
      const response = await axiosClient.post(API.AUTH.VERIFY_OTP, { email, otp });
      return response.data;
    } catch (error) {
      return rejectWithValue(getErrorMessage(error));
    }
  }
);

export const login = createAsyncThunk(
  'auth/login',
  async ({ email, password }, { rejectWithValue }) => {
    try {
      const response = await axiosClient.post(API.AUTH.LOGIN, { email, password });
      const { jwt, role, userName, email: userEmail, id } = response.data.data;
      localStorage.setItem('accessToken', jwt);
      const user = { id, name: userName, email: userEmail, role };
      localStorage.setItem('user', JSON.stringify(user));
      return { jwt, role, userName, email: userEmail, id };
    } catch (error) {
      return rejectWithValue(getErrorMessage(error));
    }
  }
);

export const forgotPassword = createAsyncThunk(
  'auth/forgotPassword',
  async (email, { rejectWithValue }) => {
    try {
      const response = await axiosClient.post(API.AUTH.FORGOT_PASSWORD, { email });
      return response.data;
    } catch (error) {
      return rejectWithValue(getErrorMessage(error));
    }
  }
);

export const verifyForgotOtp = createAsyncThunk(
  'auth/verifyForgotOtp',
  async ({ email, otp }, { rejectWithValue }) => {
    try {
      const response = await axiosClient.post(API.AUTH.VERIFY_FORGOT_OTP, { email, otp });
      return { email, success: response.data.success };
    } catch (error) {
      return rejectWithValue(getErrorMessage(error));
    }
  }
);

export const resetPassword = createAsyncThunk(
  'auth/resetPassword',
  async ({ email, password, confirmPassword }, { rejectWithValue }) => {
    try {
      const response = await axiosClient.post(API.AUTH.RESET_PASSWORD, { email, password, confirmPassword });
      return response.data;
    } catch (error) {
      return rejectWithValue(getErrorMessage(error));
    }
  }
);

export const resendOtp = createAsyncThunk(
  'auth/resendOtp',
  async ({ email, type }, { rejectWithValue }) => {
    try {
      const response = await axiosClient.post(API.AUTH.RESEND_OTP, { email, type });
      return response.data;
    } catch (error) {
      return rejectWithValue(getErrorMessage(error));
    }
  }
);

const initialState = {
  user: JSON.parse(localStorage.getItem('user')) || null,
  token: localStorage.getItem('accessToken') || null,
  pendingSignup: null,
  pendingResetEmail: null,
  isLoading: false,
  error: null,
  otpVerified: false,
};

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    logout: (state) => {
      state.user = null;
      state.token = null;
      localStorage.removeItem('accessToken');
      localStorage.removeItem('user');
    },
    clearError: (state) => {
      state.error = null;
    },
    setPendingSignup: (state, action) => {
      state.pendingSignup = action.payload;
    },
    clearPendingSignup: (state) => {
      state.pendingSignup = null;
    },
    setPendingResetEmail: (state, action) => {
      state.pendingResetEmail = action.payload;
    },
    clearPendingReset: (state) => {
      state.pendingResetEmail = null;
      state.otpVerified = false;
    },
    setOAuthUser: (state, action) => {
      const { token, refreshToken, role, email, name } = action.payload;
      const displayName = name || (email ? email.split('@')[0] : 'User');
      state.user = {
        id: null,
        name: displayName,
        email: email || null,
        role: role,
      };
      state.token = token;
      localStorage.setItem('accessToken', token);
      if (refreshToken) localStorage.setItem('refreshToken', refreshToken);
      localStorage.setItem('user', JSON.stringify(state.user));
    },
    updateUser: (state, action) => {
      if (state.user) {
        state.user = { ...state.user, ...action.payload };
        localStorage.setItem('user', JSON.stringify(state.user));
      }
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(register.pending, (state) => { state.isLoading = true; state.error = null; })
      .addCase(register.fulfilled, (state, action) => {
        state.isLoading = false;
        state.pendingSignup = action.payload.data;
      })
      .addCase(register.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      .addCase(verifyOtp.fulfilled, (state) => { state.pendingSignup = null; })
      .addCase(verifyOtp.rejected, (state, action) => { state.error = action.payload; })
      .addCase(login.pending, (state) => { state.isLoading = true; })
      .addCase(login.fulfilled, (state, action) => {
        state.isLoading = false;
        state.user = {
          id: action.payload.id,
          name: action.payload.userName,
          email: action.payload.email,
          role: action.payload.role,
        };
        state.token = action.payload.jwt;
      })
      .addCase(login.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      .addCase(forgotPassword.fulfilled, (state, action) => {
        state.pendingResetEmail = action.payload.data?.email;
      })
      .addCase(verifyForgotOtp.fulfilled, (state, action) => {
        state.otpVerified = true;
        state.pendingResetEmail = action.payload.email;
      })
      .addCase(resetPassword.fulfilled, (state) => {
        state.otpVerified = false;
        state.pendingResetEmail = null;
      });
  },
});

export const {
  logout,
  clearError,
  setPendingSignup,
  clearPendingSignup,
  setPendingResetEmail,
  clearPendingReset,
  setOAuthUser,
  updateUser,          
} = authSlice.actions;

export default authSlice.reducer;

