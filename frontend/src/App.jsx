import { Route, Routes } from "react-router-dom";

import { Navbar } from "./components/Navbar";
import { HistoryPage } from "./pages/HistoryPage";
import { HomePage } from "./pages/HomePage";
import { ResultsPage } from "./pages/ResultsPage";
import { ScannerPage } from "./pages/ScannerPage";

export default function App() {
  return (
    <div className="min-h-screen">
      <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col px-4 pb-10 pt-4 sm:px-6 lg:px-8">
        <Navbar />
        <main className="flex-1 py-8">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/scanner" element={<ScannerPage />} />
            <Route path="/results" element={<ResultsPage />} />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
