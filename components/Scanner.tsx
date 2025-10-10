// components/Scanner.tsx

'use client';

import { useState } from 'react';
import JsonDisplay from './JsonDisplay'; // <-- 1. IMPORT THE NEW COMPONENT

interface ScannerProps {
  title: string;
  description: string;
  inputLabel: string;
  onScan: (inputValue: string) => Promise<any>;
}

export default function Scanner({ title, description, onScan, inputLabel }: ScannerProps) {
  const [inputValue, setInputValue] = useState<string>('');
  const [result, setResult] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  const handleScan = async () => {
    if (!inputValue) {
      setError('Input value is required.');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await onScan(inputValue);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'An unknown error occurred.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2>{title}</h2>
      <p>{description}</p>
      <input
        type="text"
        placeholder={inputLabel}
        value={inputValue}
        onChange={(e) => setInputValue(e.target.value)}
        size={50}
      />
      <button onClick={handleScan} disabled={loading}>
        {loading ? 'Scanning...' : 'Scan'}
      </button>

      {error && <p><b>Error:</b> {error}</p>}
      
      {result && (
        <div>
          <h3>Result:</h3>
          {/* 2. REPLACE THE <pre> TAG WITH THE <JsonDisplay> COMPONENT */}
          <JsonDisplay data={result} />
        </div>
      )}
    </div>
  );
}
