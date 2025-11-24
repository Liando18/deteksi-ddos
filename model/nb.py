import numpy as np

class NaiveBayesGaussian:
    def __init__(self, model_dict):
        self.model = model_dict
        self.feature_names_in_ = model_dict['feature_names']

    def _gaussian_likelihood(self, x, mean, var):
        eps = 1e-6
        coeff = 1.0 / np.sqrt(2 * np.pi * (var + eps))
        exponent = np.exp(- (x - mean)**2 / (2 * (var + eps)))
        return coeff * exponent

    def predict(self, X):
        preds = []
        for _, row in X.iterrows():
            posteriors = {}
            for c in self.model['classes']:
                likelihoods = self._gaussian_likelihood(row.values,
                                                        self.model['mean'][c].values,
                                                        self.model['var'][c].values)
                posterior = self.model['priors'][c] * np.prod(likelihoods)
                posteriors[c] = posterior
            pred_class = max(posteriors, key=posteriors.get)
            preds.append(pred_class)
        return np.array(preds)

    def predict_proba(self, X):
        probs = []
        for _, row in X.iterrows():
            posteriors = {}
            for c in self.model['classes']:
                likelihoods = self._gaussian_likelihood(row.values,
                                                        self.model['mean'][c].values,
                                                        self.model['var'][c].values)
                posterior = self.model['priors'][c] * np.prod(likelihoods)
                posteriors[c] = posterior
            total = sum(posteriors.values())
            probs.append([posteriors[c]/total for c in self.model['classes']])
        return np.array(probs)
