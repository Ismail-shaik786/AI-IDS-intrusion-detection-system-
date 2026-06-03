import warnings
warnings.filterwarnings("ignore")
from scapy.all import *
import joblib
import numpy as np
model = joblib.load("models/multi_ids_model.pkl")
model.predict(np.zeros((1, 78)))
