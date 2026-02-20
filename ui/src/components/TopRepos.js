import React, { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function TopRepos({ repos, packages }) {
  const [view, setView] = useState('repos');
  const data = view === 'repos' ? repos : packages;
  const label = view === 'repos' ? 'repo' : 'package_name';
  const metric = view === 'repos' ? 'avg_risk' : 'avg_risk';

  return (
    <div className="section">
      <div className="section-header">
        <h3 className="section-title">
          {view === 'repos' ? 'Top 10 Repos by Risk' : 'Top 10 Packages by Vulnerability Count'}
        </h3>
        <div className="toggle-group">
          <button
            className={`toggle-btn ${view === 'repos' ? 'active' : ''}`}
            onClick={() => setView('repos')}
          >
            Repos
          </button>
          <button
            className={`toggle-btn ${view === 'packages' ? 'active' : ''}`}
            onClick={() => setView('packages')}
          >
            Packages
          </button>
        </div>
      </div>
      <div className="charts-row">
        <div className="chart-card" style={{ flex: 2 }}>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 5, right: 20, left: 100, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis type="number" domain={[0, 'auto']} tick={{ fontSize: 12 }} />
              <YAxis
                type="category"
                dataKey={label}
                tick={{ fontSize: 11 }}
                width={90}
              />
              <Tooltip />
              <Bar
                dataKey={view === 'repos' ? 'avg_risk' : 'total_vulns'}
                fill={view === 'repos' ? '#ef4444' : '#6366f1'}
                radius={[0, 4, 4, 0]}
                name={view === 'repos' ? 'Avg Risk' : 'Vulnerabilities'}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="chart-card" style={{ flex: 1 }}>
          <h4 className="chart-subtitle">Details</h4>
          <div className="detail-list">
            {data.map((item, i) => (
              <div key={i} className="detail-row">
                <span className="detail-name">{item[label]}</span>
                <div className="detail-stats">
                  <span className="detail-stat">{item.total_vulns} vulns</span>
                  {item.critical_count > 0 && (
                    <span className="badge tier-critical">{item.critical_count} crit</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
