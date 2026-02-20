import React, { useState, useEffect, useCallback } from 'react';
import { getResultsTable } from '../services/api';

export default function VulnTable({ onSelectCve }) {
  const [data, setData] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [pageSize] = useState(25);
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [sortBy, setSortBy] = useState('risk_score');
  const [sortOrder, setSortOrder] = useState('desc');
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getResultsTable({
        page,
        pageSize,
        tier: tierFilter,
        severity: sevFilter,
        search,
        sortBy,
        sortOrder,
      });
      setData(res.data);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, tierFilter, sevFilter, search, sortBy, sortOrder]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSort = (col) => {
    if (sortBy === col) {
      setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(col);
      setSortOrder('desc');
    }
    setPage(1);
  };

  const sortIcon = (col) => {
    if (sortBy !== col) return '';
    return sortOrder === 'desc' ? ' \u25BC' : ' \u25B2';
  };

  return (
    <div className="section">
      <div className="table-controls">
        <input
          type="text"
          placeholder="Search CVE, package, or repo..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          className="search-input"
        />
        <select
          value={tierFilter}
          onChange={(e) => { setTierFilter(e.target.value); setPage(1); }}
          className="filter-select"
        >
          <option value="">All Tiers</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={sevFilter}
          onChange={(e) => { setSevFilter(e.target.value); setPage(1); }}
          className="filter-select"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <span className="result-count">{total.toLocaleString()} results</span>
      </div>

      <div className="table-wrapper">
        <table className={loading ? 'loading-table' : ''}>
          <thead>
            <tr>
              <th onClick={() => handleSort('cve_id')} className="sortable">CVE ID{sortIcon('cve_id')}</th>
              <th onClick={() => handleSort('severity')} className="sortable">Severity{sortIcon('severity')}</th>
              <th onClick={() => handleSort('package_name')} className="sortable">Package{sortIcon('package_name')}</th>
              <th onClick={() => handleSort('repo')} className="sortable">Repo{sortIcon('repo')}</th>
              <th onClick={() => handleSort('cvss_score')} className="sortable">CVSS{sortIcon('cvss_score')}</th>
              <th onClick={() => handleSort('epss_score')} className="sortable">EPSS{sortIcon('epss_score')}</th>
              <th onClick={() => handleSort('ml_score')} className="sortable">ML Score{sortIcon('ml_score')}</th>
              <th onClick={() => handleSort('risk_score')} className="sortable">Risk Score{sortIcon('risk_score')}</th>
              <th onClick={() => handleSort('tier')} className="sortable">Tier{sortIcon('tier')}</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => (
              <tr key={i} onClick={() => onSelectCve(row.cve_id)} className="clickable-row">
                <td className="cve-link">{row.cve_id}</td>
                <td><span className={`badge severity-${(row.severity || '').toLowerCase()}`}>{row.severity}</span></td>
                <td>{row.package_name}</td>
                <td>{row.repo}</td>
                <td>{row.cvss_score}</td>
                <td>{row.epss_score}</td>
                <td>{row.ml_score}</td>
                <td>
                  <div className="risk-cell">
                    <div className="risk-bar-bg">
                      <div
                        className="risk-bar-fill"
                        style={{
                          width: `${(row.risk_score || 0) * 100}%`,
                          backgroundColor: row.risk_score > 0.8 ? '#dc2626' : row.risk_score > 0.6 ? '#f97316' : row.risk_score > 0.4 ? '#eab308' : '#22c55e',
                        }}
                      />
                    </div>
                    <span>{row.risk_score}</span>
                  </div>
                </td>
                <td><span className={`badge tier-${(row.tier || '').toLowerCase()}`}>{row.tier}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="pagination">
        <button
          onClick={() => setPage(p => Math.max(1, p - 1))}
          disabled={page === 1}
          className="btn btn-sm"
        >
          Previous
        </button>
        <span className="page-info">
          Page {page} of {totalPages}
        </span>
        <button
          onClick={() => setPage(p => Math.min(totalPages, p + 1))}
          disabled={page === totalPages}
          className="btn btn-sm"
        >
          Next
        </button>
      </div>
    </div>
  );
}
