import streamlit as st
import tensorflow as tf
import numpy as np
from PIL import Image, ImageOps
st.title("Image Classification")
upload_file = st.sidebar.file_uploader("Upload Chest CT-SCAN images", type = 'jpg')
generate_pred = st.sidebar.button("Diagnosis")
model = tf.keras.models.load_model('C:/Users/HP/Desktop/Project/TrainedModel.h5')
def import_n_pred(image_data, model):
    size = (128,128)
    image = ImageOps.fit(image_data, size, Image.ANTIALIAS)
    img = np.asarray(image)
    reshape = img[np.newaxis,...]
    pred = model.predict(reshape)
    return pred
if generate_pred:
    image = Image.open(upload_file)
    with st.beta_expander('image', expanded=True):
        st.image(image, use_column_width=True)
    pred = import_n_pred(image, model)
    labels = ['Bengin cases', 'Malignant cases', 'Normal cases']
    st.title("prediction of image is {}".format(labels[np.argmax(pred)])
