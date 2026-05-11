import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setOAuthUser } from '../store/slices/authSlice';
import { toast } from 'react-toastify';

export default function OAuth2RedirectPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useDispatch();

  useEffect(() => {
    const token        = searchParams.get('token');
    const refreshToken = searchParams.get('refreshToken');
    const role         = searchParams.get('role');
    const email        = searchParams.get('email');
    const name         = searchParams.get('name');
    const error        = searchParams.get('error');

    if (error) {
      toast.error(error === 'email_missing' ? 'Could not get your email from the provider.' : 'OAuth2 login failed.');
      navigate('/login', { replace: true });
      return;
    }

    if (!token || !role) {
      toast.error('Login failed — no token received.');
      navigate('/login', { replace: true });
      return;
    }

    dispatch(setOAuthUser({ token, refreshToken, role, email, name }));
    toast.success('Logged in successfully!');

    const destination = {
      INTERVIEWEE: '/interviewee',
      INTERVIEWER: '/interviewer',
      ADMIN: '/admin',
    }[role] || '/';

    navigate(destination, { replace: true });
  }, [searchParams, navigate, dispatch]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 via-purple-50 to-pink-50 flex items-center justify-center">
      <div className="text-center space-y-4">
        <div className="size-12 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center mx-auto animate-pulse">
         
        </div>
        <p className="text-gray-600 font-medium">Completing sign in...</p>
      </div>
    </div>
  );
}

