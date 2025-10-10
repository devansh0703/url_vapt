'use client';
import { useState } from 'react';
import { Shield, Search, Download, CheckCircle2, AlertCircle, Loader2, Globe, Lock, Activity, FileSearch, Wifi } from 'lucide-react';

const AVAILABLE_SCANNERS = [
  { id: 'whois', label: 'WHOIS Lookup', icon: Globe, speed: 'fast', description: 'Domain registration info' },
  { id: 'virustotal', label: 'VirusTotal', icon: Shield, speed: 'fast', description: 'Malware & threat detection' },
  { id: 'security_headers', label: 'Security Headers', icon: Lock, speed: 'fast', description: 'HTTP security analysis' },
  { id: 'crtsh', label: 'Certificate Search', icon: FileSearch, speed: 'medium', description: 'SSL/TLS certificates' },
  { id: 'bgpview', label: 'BGP View', icon: Wifi, speed: 'medium', description: 'Network routing info' },
  { id: 'ssllabs', label: 'SSL Labs', icon: Lock, speed: 'slow', description: 'Comprehensive SSL test' },
  { id: 'urlscan', label: 'URL Scan', icon: Search, speed: 'slow', description: 'Website screenshot & analysis' },
  { id: 'publicwww', label: 'PublicWWW', icon: FileSearch, speed: 'very-slow', description: 'Source code search' },
];

export default function ReportGeneratorPage() {
  const [target, setTarget] = useState('');
  const [selectedScanners, setSelectedScanners] = useState(['whois', 'virustotal']);
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState('');
  const [pdfUrl, setPdfUrl] = useState(null);

  const handleCheckboxChange = (scannerId) => {
    setSelectedScanners(prev =>
      prev.includes(scannerId)
        ? prev.filter(id => id !== scannerId)
        : [...prev, scannerId]
    );
  };

  const handleGenerateReport = async () => {
    if (!target) {
      setError('Please enter a target domain or URL.');
      return;
    }
    if (selectedScanners.length === 0) {
      setError('Please select at least one scanner.');
      return;
    }
    setIsGenerating(true);
    setError('');
    
    if (pdfUrl) {
      URL.revokeObjectURL(pdfUrl);
      setPdfUrl(null);
    }
    
    try {
      const response = await fetch('http://127.0.0.1:8000/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target,
          scanners: selectedScanners,
        }),
      });
      
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Failed to generate report.');
      }
      
      const pdfBlob = await response.blob();
      const url = URL.createObjectURL(pdfBlob);
      setPdfUrl(url);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsGenerating(false);
    }
  };

  const getSpeedBadgeColor = (speed) => {
    switch(speed) {
      case 'fast': return 'bg-emerald-500/20 text-emerald-400';
      case 'medium': return 'bg-amber-500/20 text-amber-400';
      case 'slow': return 'bg-orange-500/20 text-orange-400';
      case 'very-slow': return 'bg-red-500/20 text-red-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950">
      {/* Animated background effect */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute w-96 h-96 bg-blue-500/10 rounded-full blur-3xl -top-48 -left-48 animate-pulse"></div>
        <div className="absolute w-96 h-96 bg-purple-500/10 rounded-full blur-3xl -bottom-48 -right-48 animate-pulse delay-1000"></div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <div className="relative">
              <Shield className="w-16 h-16 text-blue-400" strokeWidth={1.5} />
              <div className="absolute inset-0 bg-blue-400/20 blur-xl rounded-full"></div>
            </div>
          </div>
          <h1 className="text-5xl font-bold text-white mb-3 tracking-tight">
            Deep<span className="text-blue-400">Cytes</span>
          </h1>
          <p className="text-slate-400 text-lg">Advanced URL Security Scanner</p>
        </div>

        {/* Main Card */}
        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
          {/* Target Input Section */}
          <div className="p-8 border-b border-slate-800">
            <label className="block text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
              <Globe className="w-4 h-4" />
              Target URL or Domain
            </label>
            <div className="relative">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or https://example.com"
                className="w-full px-5 py-4 bg-slate-800/50 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
              />
              <Search className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
            </div>
          </div>

          {/* Scanner Selection */}
          <div className="p-8 border-b border-slate-800">
            <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-400" />
              Select Scanners
              <span className="ml-auto text-sm font-normal text-slate-400">
                {selectedScanners.length} selected
              </span>
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {AVAILABLE_SCANNERS.map(scanner => {
                const Icon = scanner.icon;
                const isSelected = selectedScanners.includes(scanner.id);
                
                return (
                  <div
                    key={scanner.id}
                    onClick={() => handleCheckboxChange(scanner.id)}
                    className={`relative p-4 rounded-xl border-2 cursor-pointer transition-all duration-200 ${
                      isSelected
                        ? 'bg-blue-500/10 border-blue-500 shadow-lg shadow-blue-500/20'
                        : 'bg-slate-800/30 border-slate-700 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${isSelected ? 'bg-blue-500/20' : 'bg-slate-700/50'}`}>
                        <Icon className={`w-5 h-5 ${isSelected ? 'text-blue-400' : 'text-slate-400'}`} />
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className={`font-semibold text-sm ${isSelected ? 'text-white' : 'text-slate-300'}`}>
                            {scanner.label}
                          </h4>
                          {isSelected && (
                            <CheckCircle2 className="w-4 h-4 text-blue-400 flex-shrink-0" />
                          )}
                        </div>
                        <p className="text-xs text-slate-500 mb-2">{scanner.description}</p>
                        <span className={`inline-block px-2 py-1 text-xs font-medium rounded-md ${getSpeedBadgeColor(scanner.speed)}`}>
                          {scanner.speed.replace('-', ' ')}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Generate Button Section */}
          <div className="p-8">
            <button
              onClick={handleGenerateReport}
              disabled={isGenerating || !target || selectedScanners.length === 0}
              className="w-full py-4 px-6 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white font-semibold rounded-xl shadow-lg shadow-blue-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center gap-3 group"
            >
              {isGenerating ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Generating Security Report...
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5 group-hover:scale-110 transition-transform" />
                  Generate Security Report
                </>
              )}
            </button>

            {error && (
              <div className="mt-4 p-4 bg-red-500/10 border border-red-500/50 rounded-xl flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <p className="text-red-300 text-sm">{error}</p>
              </div>
            )}
          </div>
        </div>

        {/* Report Preview */}
        {pdfUrl && (
          <div className="mt-8 bg-slate-900/50 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
            <div className="p-6 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-500/20 rounded-lg">
                  <CheckCircle2 className="w-5 h-5 text-green-400" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Security Report Generated</h2>
                  <p className="text-sm text-slate-400">Target: {target}</p>
                </div>
              </div>
              
              <a
                href={pdfUrl}
                download={`DeepCytes_Security_Report_${target}.pdf`}
                className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg transition-colors"
              >
                <Download className="w-4 h-4" />
                Download PDF
              </a>
            </div>
            
            <div className="p-4">
              <iframe 
                src={pdfUrl} 
                className="w-full h-[800px] rounded-lg border border-slate-700"
                title="Security Report"
              />
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="text-center mt-12 text-slate-500 text-sm">
          <p>Powered by AI-driven threat intelligence and security analysis</p>
        </div>
      </div>
    </div>
  );
}
