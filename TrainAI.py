import numpy as np
import pandas as pd

dataset = pd.read_csv('./random_dataset.csv')
X = dataset.iloc[:,[0,1,2,3,4,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51]].values
Y = dataset.iloc[:,-1].values


# from sklearn.impute import SimpleImputer
# imputer = SimpleImputer(missing_values=np.nan,strategy='most_frequent')
# X = imputer.fit_transform(X)
# Y = imputer.fit_transform(Y)



# from sklearn.preprocessing import StandardScaler
# sc = StandardScaler()
# X = sc.fit_transform(X)

# Y = Y.reshape(-1,1)

from sklearn.impute import SimpleImputer
imputer = SimpleImputer(missing_values=np.nan,strategy='most_frequent')
X = imputer.fit_transform(X)
# Y = imputer.fit_transform(Y)

from sklearn.preprocessing import LabelEncoder
le2 = LabelEncoder()
X[:,2] = le2.fit_transform(X[:,2])
le3 = LabelEncoder()
X[:,3] = le3.fit_transform(X[:,3])
le4 = LabelEncoder()
X[:,4] = le4.fit_transform(X[:,4])
le5 = LabelEncoder()
X[:,5] = le4.fit_transform(X[:,5])
le6 = LabelEncoder()
Y = le6.fit_transform(Y)

# from sklearn.calibration import column_or_1d
# Y = column_or_1d(Y, warn = True)

# print(Y)

from sklearn.preprocessing import StandardScaler
sc = StandardScaler()
X = sc.fit_transform(X)

# print(X)
# print(Y)

from sklearn.model_selection import train_test_split
X_train,X_test,Y_train,Y_test = train_test_split(X,Y,test_size=0.2,random_state=0)

from sklearn.ensemble import RandomForestClassifier
classifier = RandomForestClassifier(n_estimators=100,random_state=0)

classifier.fit(X_train,Y_train)

# print(classifier.score(X_train,Y_train))

y_pred = le6.inverse_transform(np.array(classifier.predict(X_test),dtype=int))
Y_test = le6.inverse_transform(np.array(Y_test,dtype=int))

# print(y_pred)
y_pred = y_pred.reshape(-1,1)
Y_test = Y_test.reshape(-1,1)

df = np.concatenate((Y_test,y_pred),axis=1)
dataframe = pd.DataFrame(df,columns=['Rain on Tommorrow','Predition of Rain'])

print(dataframe)

from sklearn.metrics import accuracy_score
print(accuracy_score(Y_test,y_pred))
# print(X)

# print(Y)