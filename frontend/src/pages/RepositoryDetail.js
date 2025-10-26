import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { AlertTriangle, Shield, Info, FileCode, ArrowLeft, Calendar, Code, Sparkles } from 'lucide-react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '../components/ui/accordion';
import { toast } from 'sonner';
import { AIFixModal } from '../components/AIFixModal';

export default function RepositoryDetail({ user }) {
  const { repoId } = useParams();
  const navigate = useNavigate();
  const [repository, setRepository] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [showAIFixModal, setShowAIFixModal] = useState(false);
  const [severityCounts, setSeverityCounts] = useState({});

  useEffect(() => {
    fetchRepositoryDetails();
  }, [repoId]);

  const fetchRepositoryDetails = async () => {
    try {
      setLoading(true);
      
      // Fetch repository info
      const repoResponse = await axios.get(`${API}/repositories/${repoId}`);
      setRepository(repoResponse.data);
      
      // Fetch vulnerabilities for this repository
      const vulnResponse = await axios.get(`${API}/repositories/${repoId}/vulnerabilities`);
      setVulnerabilities(vulnResponse.data.vulnerabilities || []);
      setSeverityCounts(vulnResponse.data.severity_counts || {});
    } catch (error) {
      if (error.response?.status === 404) {
        toast.error('Repository not found');
        navigate('/repositories');
      } else {
        toast.error('Failed to fetch repository details');
      }
    } finally {
      setLoading(false);
    }
  };

  const getSeverityIcon = (severity) => {
    const icons = {
      critical: <AlertTriangle className="w-5 h-5 text-red-600" />,
      high: <AlertTriangle className="w-5 h-5 text-orange-600" />,
      medium: <AlertTriangle className="w-5 h-5 text-yellow-600" />,
      low: <Info className="w-5 h-5 text-blue-600" />,
      info: <Info className="w-5 h-5 text-gray-600" />
    };
    return icons[severity] || icons.info;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-blue-100 text-blue-800 border-blue-200',
      info: 'bg-gray-100 text-gray-800 border-gray-200'
    };
    return colors[severity] || colors.info;
  };

  const getScoreColor = (score) => {
    if (!score) return 'text-gray-400';
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  const filteredVulnerabilities = severityFilter === 'all'
    ? vulnerabilities
    : vulnerabilities.filter(v => v.severity === severityFilter);

  const totalCounts = {
    all: vulnerabilities.length,
    critical: severityCounts.critical || 0,
    high: severityCounts.high || 0,
    medium: severityCounts.medium || 0,
    low: severityCounts.low || 0,
    info: severityCounts.info || 0,
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
        <Navigation user={user} />
        <div className="flex items-center justify-center h-[80vh]">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      </div>
    );
  }

  if (!repository) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <Navigation user={user} />
      
      <div className="max-w-7xl mx-auto p-6 lg:p-8">
        {/* Back Button */}
        <Button
          variant="ghost"
          onClick={() => navigate('/repositories')}
          className="mb-6"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Repositories
        </Button>

        {/* Repository Header */}
        <Card className="bg-white/80 backdrop-blur-sm border-gray-200 mb-8">
          <CardHeader>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-4">
                  <Code className="w-8 h-8 text-blue-600" />
                  <div>
                    <CardTitle className="text-3xl mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                      {repository.name}
                    </CardTitle>
                    {repository.description && (
                      <p className="text-gray-600">{repository.description}</p>
                    )}
                  </div>
                </div>
                
                <div className="flex flex-wrap items-center gap-4">
                  <Badge variant="outline" className="capitalize">
                    {repository.language}
                  </Badge>
                  
                  {repository.github_url && (
                    <a
                      href={repository.github_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-blue-600 hover:text-blue-800 underline"
                    >
                      View on GitHub
                    </a>
                  )}
                  
                  {repository.last_scan && (
                    <div className="flex items-center gap-2 text-sm text-gray-600">
                      <Calendar className="w-4 h-4" />
                      Last scan: {new Date(repository.last_scan).toLocaleDateString()}
                    </div>
                  )}
                </div>
              </div>
              
              {/* Security Score */}
              {repository.security_score !== null && repository.security_score !== undefined && (
                <div className="text-center">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="w-5 h-5 text-gray-600" />
                    <span className="text-sm text-gray-600">Security Score</span>
                  </div>
                  <div className={`text-4xl font-bold ${getScoreColor(repository.security_score)}`}>
                    {repository.security_score}
                  </div>
                </div>
              )}
            </div>
          </CardHeader>
        </Card>

        {/* Vulnerabilities Section */}
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-4" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            Security Vulnerabilities
          </h2>
          <p className="text-gray-600 mb-6">
            Found {totalCounts.all} {totalCounts.all === 1 ? 'vulnerability' : 'vulnerabilities'} in this repository
          </p>
        </div>

        {/* Filters and Stats */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <span>Showing {filteredVulnerabilities.length} of {totalCounts.all} vulnerabilities</span>
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-[200px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All ({totalCounts.all})</SelectItem>
              <SelectItem value="critical">Critical ({totalCounts.critical})</SelectItem>
              <SelectItem value="high">High ({totalCounts.high})</SelectItem>
              <SelectItem value="medium">Medium ({totalCounts.medium})</SelectItem>
              <SelectItem value="low">Low ({totalCounts.low})</SelectItem>
              <SelectItem value="info">Info ({totalCounts.info})</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Vulnerabilities List */}
        {filteredVulnerabilities.length > 0 ? (
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200">
            <CardContent className="p-6">
              <Accordion type="single" collapsible className="space-y-4">
                {filteredVulnerabilities.map((vuln, index) => (
                  <AccordionItem 
                    key={vuln.id} 
                    value={vuln.id} 
                    className="border rounded-xl px-4 bg-gray-50"
                  >
                    <AccordionTrigger className="hover:no-underline py-4">
                      <div className="flex items-center gap-3 text-left w-full">
                        {getSeverityIcon(vuln.severity)}
                        <div className="flex-1">
                          <div className="font-semibold text-gray-900 mb-1">{vuln.title}</div>
                          <div className="flex items-center gap-3 flex-wrap">
                            <Badge className={`${getSeverityColor(vuln.severity)} text-xs capitalize`}>
                              {vuln.severity}
                            </Badge>
                            {vuln.file_path && (
                              <div className="flex items-center gap-1 text-xs text-gray-600">
                                <FileCode className="w-3 h-3" />
                                {vuln.file_path}
                              </div>
                            )}
                            {vuln.line_number && (
                              <span className="text-xs text-gray-600">
                                Line {vuln.line_number}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="pb-4 pt-2">
                      <div className="space-y-4 text-sm">
                        {/* Description */}
                        <div>
                          <p className="font-semibold text-gray-700 mb-2">Description:</p>
                          <p className="text-gray-600 leading-relaxed">{vuln.description}</p>
                        </div>

                        {/* Code Snippet */}
                        {vuln.code_snippet && (
                          <div>
                            <p className="font-semibold text-gray-700 mb-2">Code Snippet:</p>
                            <div className="bg-gray-900 text-gray-100 p-3 rounded-lg overflow-x-auto">
                              <pre className="text-xs font-mono">{vuln.code_snippet}</pre>
                            </div>
                          </div>
                        )}

                        {/* Metadata */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {vuln.cwe_id && (
                            <div>
                              <p className="font-semibold text-gray-700 mb-1">CWE ID:</p>
                              <Badge variant="outline" className="text-xs">{vuln.cwe_id}</Badge>
                            </div>
                          )}

                          {vuln.owasp_category && (
                            <div>
                              <p className="font-semibold text-gray-700 mb-1">OWASP Category:</p>
                              <Badge variant="outline" className="text-xs">{vuln.owasp_category}</Badge>
                            </div>
                          )}
                        </div>

                        {/* Remediation */}
                        {vuln.remediation && (
                          <div>
                            <p className="font-semibold text-gray-700 mb-2">How to Fix:</p>
                            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                              <p className="text-gray-700 leading-relaxed">{vuln.remediation}</p>
                            </div>
                          </div>
                        )}

                        {/* AI Fix Button */}
                        <div className="pt-4 border-t">
                          <Button
                            onClick={() => {
                              setSelectedVulnerability(vuln);
                              setShowAIFixModal(true);
                            }}
                            className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700"
                          >
                            <Sparkles className="w-4 h-4 mr-2" />
                            Generate AI-Powered Fix
                          </Button>
                        </div>

                        {/* Timestamp */}
                        <div className="text-xs text-gray-500 pt-2 border-t">
                          Found: {new Date(vuln.created_at).toLocaleString()}
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </CardContent>
          </Card>
        ) : (
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200 border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-16">
              <Shield className="w-16 h-16 text-gray-400 mb-4" />
              <h3 className="text-lg font-semibold text-gray-700 mb-2">
                {severityFilter === 'all' ? 'No Vulnerabilities Found' : `No ${severityFilter} Vulnerabilities`}
              </h3>
              <p className="text-gray-500 text-center max-w-sm">
                {severityFilter === 'all'
                  ? 'This repository has no detected vulnerabilities. Great job!'
                  : `No vulnerabilities with ${severityFilter} severity found. Try a different filter.`}
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
