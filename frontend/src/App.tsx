import { RouterProvider, createRouter, createRoute, createRootRoute, redirect } from '@tanstack/react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Users } from './pages/admin/Users';
import { Configs } from './pages/Configs';
import { Scans } from './pages/Scans';
import { NewScan } from './pages/NewScan';
import { ScanEdit } from './pages/ScanEdit';
import { ScanDetail } from './pages/ScanDetail';
import { ComparisonView } from './pages/ComparisonView';
import { ScheduledScans } from './pages/ScheduledScans';
import { ScheduledScanForm } from './pages/ScheduledScanForm';
import { useAuth } from './hooks/useAuth';

const queryClient = new QueryClient();

const rootRoute = createRootRoute();

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
});

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/dashboard',
  component: Dashboard,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const usersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/admin/users',
  component: Users,
  beforeLoad: () => {
    const { user, isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
    if (!user?.is_admin) {
      throw redirect({ to: '/dashboard' });
    }
  },
});

const configsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/configs',
  component: Configs,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const scansRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans',
  component: Scans,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const newScanRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans/new',
  component: NewScan,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const scanDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans/$scanId',
  component: ScanDetail,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const scanEditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans/$scanId/edit',
  component: ScanEdit,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const comparisonRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/comparisons/$comparisonId',
  component: ComparisonView,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const scheduledScansRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scheduled-scans',
  component: ScheduledScans,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const scheduledScanFormRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scheduled-scans/$scheduledScanId',
  component: ScheduledScanForm,
  beforeLoad: () => {
    const { isAuthenticated } = useAuth.getState();
    if (!isAuthenticated) {
      throw redirect({ to: '/login' });
    }
  },
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: () => {
    const { isAuthenticated } = useAuth();
    if (isAuthenticated) {
      window.location.href = '/dashboard';
    } else {
      window.location.href = '/login';
    }
    return null;
  },
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  dashboardRoute,
  usersRoute,
  configsRoute,
  scansRoute,
  newScanRoute,
  scanDetailRoute,
  scanEditRoute,
  comparisonRoute,
  scheduledScansRoute,
  scheduledScanFormRoute,
  indexRoute,
]);
const router = createRouter({ routeTree });

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <Toaster position="top-right" />
    </QueryClientProvider>
  );
}
