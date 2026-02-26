import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
});

export async function uploadCSV(file) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await api.post('/api/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return res.data;
}

export async function scoreSample(n = 500) {
  const res = await api.post(`/api/score/sample?n=${n}`);
  return res.data;
}

export async function getResults() {
  const res = await api.get('/api/results');
  return res.data;
}

export async function getResultsTable({ page, pageSize, tier, severity, search, sortBy, sortOrder }) {
  const params = new URLSearchParams();
  params.append('page', page || 1);
  params.append('page_size', pageSize || 25);
  if (tier) params.append('tier', tier);
  if (severity) params.append('severity', severity);
  if (search) params.append('search', search);
  if (sortBy) params.append('sort_by', sortBy);
  if (sortOrder) params.append('sort_order', sortOrder);
  const res = await api.get(`/api/results/table?${params.toString()}`);
  return res.data;
}

export async function getVulnerabilityDetail(cveId) {
  const res = await api.get(`/api/vulnerability/${encodeURIComponent(cveId)}`);
  return res.data;
}

export async function getModelInfo() {
  const res = await api.get('/api/model/info');
  return res.data;
}

export async function checkHealth() {
  const res = await api.get('/api/health');
  return res.data;
}

export async function getExplanation(cveId) {
  const res = await api.get(`/api/explain/${encodeURIComponent(cveId)}`);
  return res.data;
}

export async function getPortfolioInsights() {
  const res = await api.get('/api/explain/portfolio');
  return res.data;
}

export async function getRepos() {
  const res = await api.get('/api/repos');
  return res.data;
}

export async function getReleaseComparisonStats(repo, currentRelease, previousRelease) {
  const params = new URLSearchParams();
  if (currentRelease) params.append('current_release', currentRelease);
  if (previousRelease) params.append('previous_release', previousRelease);
  const query = params.toString() ? `?${params.toString()}` : '';
  const res = await api.get(`/api/release-comparison/${encodeURIComponent(repo)}/stats${query}`);
  return res.data;
}

export async function getReleaseComparisonInsights(repo, currentRelease, previousRelease) {
  const params = new URLSearchParams();
  if (currentRelease) params.append('current_release', currentRelease);
  if (previousRelease) params.append('previous_release', previousRelease);
  const query = params.toString() ? `?${params.toString()}` : '';
  const res = await api.get(`/api/explain/release-comparison/${encodeURIComponent(repo)}${query}`);
  return res.data;
}
