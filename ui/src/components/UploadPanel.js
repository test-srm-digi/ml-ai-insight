import React, { useRef, useState } from 'react';
import { uploadCSV, scoreSample } from '../services/api';

export default function UploadPanel({ onDataLoaded, onError, loading, setLoading }) {
  const fileInputRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);
  const [sampleSize, setSampleSize] = useState(500);

  const handleFile = async (file) => {
    if (!file) return;
    if (!file.name.match(/\.(csv|xlsx?)$/i)) {
      onError('Please upload a CSV or Excel file.');
      return;
    }
    setLoading(true);
    try {
      const data = await uploadCSV(file);
      onDataLoaded(data);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Upload failed';
      onError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    handleFile(file);
  };

  const handleSample = async () => {
    setLoading(true);
    try {
      const data = await scoreSample(sampleSize);
      onDataLoaded(data);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Failed to generate sample';
      onError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="upload-panel">
      <div
        className={`drop-zone ${dragOver ? 'drag-over' : ''} ${loading ? 'loading' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => !loading && fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv,.xlsx,.xls"
          style={{ display: 'none' }}
          onChange={(e) => handleFile(e.target.files[0])}
        />
        {loading ? (
          <div className="spinner-container">
            <div className="spinner" />
            <p>Processing vulnerabilities...</p>
          </div>
        ) : (
          <>
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#6b7280" strokeWidth="1.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
            <p className="drop-text">Drop CSV file here or click to upload</p>
            <p className="drop-hint">Supports CSV, Excel (.xlsx, .xls) files</p>
          </>
        )}
      </div>
      <div className="sample-section">
        <span className="or-divider">or</span>
        <div className="sample-controls">
          <label>
            Sample size:
            <input
              type="number"
              min="10"
              max="5000"
              value={sampleSize}
              onChange={(e) => setSampleSize(Number(e.target.value))}
              className="sample-input"
            />
          </label>
          <button onClick={handleSample} disabled={loading} className="btn btn-secondary">
            Generate Sample Data
          </button>
        </div>
      </div>
    </div>
  );
}
