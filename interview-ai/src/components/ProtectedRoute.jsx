import { Navigate, Outlet } from 'react-router-dom';
import { useSelector } from 'react-redux';

export default function ProtectedRoute({ allowedRoles }) {
  const { user, token } = useSelector((state) => state.auth);
  if (!token || !user) return <Navigate to="/login" replace />;
  const userRole = user.role?.toLowerCase();
  if (allowedRoles && !allowedRoles.includes(userRole)) {
    return <Navigate to="/" replace />;
  }
  return <Outlet />;
}