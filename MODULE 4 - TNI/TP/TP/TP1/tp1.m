
%============ TP1 : BAHIDA--YOUSSEF : 09-03-2026 : 23:30 ============

% Question 1 ---------------------------------------------

    % Lire une image d'un oiseau.jpg
    image = imread("oiseau.jpg");
    
    % Afficher l'image
    imshow(image);
    
    % Construire la composante rouge de l'image (-r,g,b)
    compos_rouge = zeros(size(image),"uint8");
    compos_rouge(:,:,1) = image(:,:,1);
    imshow(compos_rouge);
    % Construire la composante verte de l'image (r,-g,b)
    compos_verte = zeros(size(image),"uint8");
    compos_verte(:,:,2) = image(:,:,2);
    imshow(compos_verte);
    % Construire la composante bleue de l'image (r,g,-b)
    compos_bleue = zeros(size(image),"uint8");
    compos_bleue(:,:,3) = image(:,:,3);
    imshow(compos_bleue);


% Question 2 ---------------------------------------------

    % Conversions
    dbImg = double(image); 
    db255Img = double(image)/ 255;
    dbfuncImg = im2double(image);
    
    % Affichage 
    imshow(dbImg);       % Majorité des valeurs > 1.0 donc que des blancs

    imshow(db255Img);    % des valeurs entre 0.0 et 1.0, matlab comprend 
                         % type double entre 0.0 et 1.0 (manuel)

    imshow(dbfuncImg);   % des valeurs entre 0.0 et 1.0, mais 
                         % automatiquement via fonction imageToDouble


% Question 3 ---------------------------------------------

    % Conversion au niveau de gris
    grayImg = im2gray(image);
    binImg  = imbinarize(grayImg);
    [indice,rgbMat] = rgb2ind(image,16); % réduire les couleurs à 16 

    % Affichage  avec subplot
    figure('Name',"Traitement d'une image");

    subplot(2,3,1);imshow(grayImg);title("Intensité");
    subplot(2,3,2);imshow(binImg);title("binaire");
    subplot(2,3,3);imshow(indice,rgbMat);title("indexée");

    subplot(2,3,4);imshow(compos_rouge);title("composante rouge");
    subplot(2,3,5);imshow(compos_verte);title("composante verte");
    subplot(2,3,6);imshow(compos_bleue);title("composante bleue");

    %subplot(3,3,7);imshow(dbImg);
    %subplot(3,3,8);imshow(db255Img);
    %subplot(3,3,9);imshow(dbfuncImg);


% Question 4 ---------------------------------------------

  % Affichage des fonctions de manipulation
    
    %figure("Name","Informations d'image");imageinfo(imshow(image));
    %zoom on;
    %figure("Name","Crop");[img_crop, rect]=imcrop(image);imshow(img_crop);
    %figure("Name","Profile"); imshow(image);improfile;
    %figure("Name","Pixels cliqués"); imshow(image); impixel(image);
    %figure("Name","Pixel Info"); imshow(image); impixelinfo;
    %figure("Name","Pixel Region"); impixelregion(imshow(image));
    %figure("Name","Distance"); imshow(image); imdistline;
    %figure("Name","Display Range"); imshow(image); imdisplayrange;
    %figure("Name","Contraste");imcontrast(imshow(rgb2gray(image)));
    %imageViewer(image); %imtool est obsolète

    %{
    figure("Name","Resize x4"); 
    imshow(imresize(image,4.0), 'InitialMagnification', 100);
    axis on;
    figure("Name","Resize x20"); 
    imshow(imresize(image,20.0), 'InitialMagnification', 100);
    axis on;
    %}

    %figure("Name","Rotation"); imshow(imrotate(image,45));



%======================  FIN : 09-03-2026 ============================