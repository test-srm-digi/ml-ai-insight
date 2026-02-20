import React, { useState } from 'react';

/**
 * AiInsights — renders the 3-section LLM explanation:
 *   I.  Context-Awareness & Summarisation
 *   II. Impact, Health & Blast Radius
 *   III. Remedy & Actionable Plans
 *
 * Props:
 *   context  — string (markdown-ish text from LLM)
 *   impact   — string
 *   remedy   — string
 *   loading  — boolean
 *   error    — string | null
 *   onRetry  — function (optional)
 */
export default function AiInsights({ context, impact, remedy, loading, error, onRetry }) {
  const [activeSection, setActiveSection] = useState('context');

  if (loading) {
    return (
      <div className="ai-insights">
        <div className="ai-insights-loading">
          <div className="spinner" />
          <span className="ai-loading-text">Generating AI analysis...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="ai-insights">
        <div className="ai-insights-error">
          <span>Failed to generate AI insights: {error}</span>
          {onRetry && (
            <button className="btn btn-sm" onClick={onRetry} style={{ marginLeft: 12 }}>
              Retry
            </button>
          )}
        </div>
      </div>
    );
  }

  if (!context && !impact && !remedy) {
    return null;
  }

  const sections = [
    { key: 'context', label: 'Context & Summary', icon: 'I', content: context },
    { key: 'impact', label: 'Impact & Blast Radius', icon: 'II', content: impact },
    { key: 'remedy', label: 'Remedy & Action Plan', icon: 'III', content: remedy },
  ];

  const activeContent = sections.find(s => s.key === activeSection)?.content || '';

  return (
    <div className="ai-insights">
      <div className="ai-insights-tabs">
        {sections.map((s) => (
          <button
            key={s.key}
            className={`ai-tab ${activeSection === s.key ? 'active' : ''}`}
            onClick={() => setActiveSection(s.key)}
          >
            <span className="ai-tab-icon">{s.icon}</span>
            <span className="ai-tab-label">{s.label}</span>
          </button>
        ))}
      </div>
      <div className="ai-insights-content">
        {activeContent ? (
          <div className="ai-text">
            {activeContent.split('\n').map((line, i) => {
              if (!line.trim()) return <br key={i} />;
              if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
                return (
                  <div key={i} className="ai-bullet">
                    <span className="ai-bullet-dot" />
                    <span>{renderBold(line.trim().slice(2))}</span>
                  </div>
                );
              }
              if (line.trim().startsWith('**') && line.trim().endsWith('**')) {
                return <p key={i} className="ai-subheading">{line.trim().replace(/\*\*/g, '')}</p>;
              }
              return <p key={i}>{renderBold(line)}</p>;
            })}
          </div>
        ) : (
          <p className="ai-no-data">No data available for this section.</p>
        )}
      </div>
    </div>
  );
}

/** Simple bold renderer for **text** patterns. */
function renderBold(text) {
  if (!text) return text;
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    return part;
  });
}
