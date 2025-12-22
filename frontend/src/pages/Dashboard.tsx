import { Navigation } from '../components/Navigation';

export function Dashboard() {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900" data-component="DashboardPage">
      <Navigation />

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="border-4 border-dashed border-gray-200 dark:border-gray-700 rounded-lg h-96 flex items-center justify-center" data-testid="dashboard-placeholder">
            <p className="text-gray-500 dark:text-gray-400 text-lg">
              Dashboard coming soon in Phase 1B!
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
