"""
Deep Forensics - Copy-Move Detection Engine
Uses SIFT/ORB feature extraction + custom clustering via OpenCV
"""

import os
import shutil

# Try to import heavy dependencies; if unavailable, provide a lightweight fallback
HAS_FULL_IMPL = True
IMPORT_ERROR = None
try:
    import cv2
    import numpy as np
    # Try sklearn for DBSCAN clustering
    try:
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import StandardScaler
        HAS_SKLEARN = True
    except ImportError:
        HAS_SKLEARN = False
except Exception as e:
    HAS_FULL_IMPL = False
    IMPORT_ERROR = str(e)


if not HAS_FULL_IMPL:
    class CopyMoveDetector:
        def __init__(self, method="SIFT"):
            self.method = method
            print(f"[ERROR] Missing required dependencies: {IMPORT_ERROR}")
            print("[ERROR] Please install: pip install opencv-contrib-python scikit-learn numpy")

        def detect(self, image_path):
            # Lightweight fallback: copy the uploaded image to results and report no forgery.
            result_path = image_path.replace("uploads", "results").replace(
                os.path.splitext(image_path)[-1], "_result.jpg"
            )
            os.makedirs(os.path.dirname(result_path), exist_ok=True)
            try:
                shutil.copy(image_path, result_path)
            except Exception:
                # If copy fails, point to the original image (still web-accessible)
                result_path = image_path

            return {
                "detected": False,
                "confidence": 0,
                "total_keypoints": 0,
                "total_matches": 0,
                "suspicious_pairs": 0,
                "clusters_found": 0,
                "result_image": result_path,
                "message": "Dependencies missing. Analysis not performed. Run: pip install opencv-contrib-python scikit-learn numpy",
            }


else:
    import cv2
    import numpy as np
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler


    class CopyMoveDetector:
        def __init__(self, method="SIFT"):
            """
            Initialize detector.
            method: "SIFT" (better accuracy), "ORB" (faster), or "auto" (automatic selection)
            """
            self.method = method
            self._init_detector()

        def _init_detector(self):
            if self.method == "auto":
                # Auto mode: Try SIFT first, fallback to ORB if SIFT unavailable
                try:
                    self.detector = cv2.SIFT_create(nfeatures=1000)
                    self.method = "SIFT"  # Update method to reflect actual used algorithm
                except AttributeError:
                    try:
                        self.detector = cv2.xfeatures2d.SIFT_create(nfeatures=1000)
                        self.method = "SIFT"
                    except AttributeError:
                        # SIFT not available (needs opencv-contrib-python)
                        print("[WARNING] SIFT not available, falling back to ORB")
                        self.detector = cv2.ORB_create(nfeatures=1000)
                        self.method = "ORB"
            elif self.method == "SIFT":
                try:
                    self.detector = cv2.SIFT_create(nfeatures=1000)
                except AttributeError:
                    try:
                        # Fallback for older OpenCV builds
                        self.detector = cv2.xfeatures2d.SIFT_create(nfeatures=1000)
                    except AttributeError:
                        # SIFT not available - raise error to let user know
                        raise ValueError(
                            "SIFT algorithm not available. Please install opencv-contrib-python: "
                            "pip install opencv-contrib-python"
                        )
            else:
                self.detector = cv2.ORB_create(nfeatures=1000)

        def detect(self, image_path):
            """
            Full detection pipeline.
            Returns: dict with result info, annotated image path
            """
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError(f"Could not load image: {image_path}")

            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Step 1: Extract keypoints and descriptors
            keypoints, descriptors = self.detector.detectAndCompute(gray, None)

            if descriptors is None or len(keypoints) < 10:
                return self._no_detection_result(img, image_path)

            # Step 2: Match features (brute force or FLANN)
            matches = self._match_features(descriptors)

            if not matches:
                return self._no_detection_result(img, image_path)

            # Step 3: Filter matches by distance between source/destination keypoints
            suspicious_pairs = self._filter_suspicious_pairs(keypoints, matches)

            if len(suspicious_pairs) < 4:
                return self._no_detection_result(img, image_path)

            # Step 4: Cluster suspicious regions with DBSCAN
            region_mask, clusters = self._cluster_regions(img.shape, suspicious_pairs)

            # Step 5: Draw results on image
            annotated = self._draw_results(img.copy(), suspicious_pairs, region_mask)

            # Save annotated image
            result_path = image_path.replace("uploads", "results").replace(
                os.path.splitext(image_path)[-1], "_result.jpg"
            )
            cv2.imwrite(result_path, annotated)

            confidence = min(100, int(len(suspicious_pairs) / max(len(matches), 1) * 100 * 3))
            confidence = max(confidence, 55) if len(suspicious_pairs) >= 4 else 0

            return {
                "detected": True,
                "confidence": confidence,
                "total_keypoints": len(keypoints),
                "total_matches": len(matches),
                "suspicious_pairs": len(suspicious_pairs),
                "clusters_found": clusters,
                "result_image": result_path,
                "message": f"Copy-move forgery detected with {confidence}% confidence.",
            }

        def _match_features(self, descriptors):
            if self.method == "SIFT":
                matcher = cv2.BFMatcher(cv2.NORM_L2)
            else:
                matcher = cv2.BFMatcher(cv2.NORM_HAMMING)

            if len(descriptors) < 2:
                return []

            matches = matcher.knnMatch(descriptors, descriptors, k=3)
            good = []
            for match_group in matches:
                # Skip self-match (distance ~ 0)
                filtered = [m for m in match_group if m.distance > 1e-4]
                if len(filtered) >= 2:
                    if filtered[0].distance < 0.75 * filtered[1].distance:
                        good.append(filtered[0])
            return good

        def _filter_suspicious_pairs(self, keypoints, matches):
            """Keep only pairs where source and destination are spatially separated."""
            suspicious = []
            for m in matches:
                pt1 = np.array(keypoints[m.queryIdx].pt)
                pt2 = np.array(keypoints[m.trainIdx].pt)
                dist = np.linalg.norm(pt1 - pt2)
                if dist > 20:  # at least 20px apart
                    suspicious.append((pt1, pt2))
            return suspicious

        def _cluster_regions(self, img_shape, pairs):
            """Find dense clusters of copy-move regions using simple distance-based clustering."""
            pts = np.array([p[0] for p in pairs] + [p[1] for p in pairs])
            if len(pts) < 4:
                return None, 0

            # Use sklearn if available, otherwise use simple clustering
            if HAS_SKLEARN:
                try:
                    scaler = StandardScaler()
                    pts_scaled = scaler.fit_transform(pts)
                    db = DBSCAN(eps=0.5, min_samples=3).fit(pts_scaled)
                    n_clusters = len(set(db.labels_)) - (1 if -1 in db.labels_ else 0)
                except Exception:
                    n_clusters = self._simple_clustering(pts)
            else:
                n_clusters = self._simple_clustering(pts)

            mask = np.zeros(img_shape[:2], dtype=np.uint8)
            for pt in pts:
                cv2.circle(mask, (int(pt[0]), int(pt[1])), 15, 255, -1)

            return mask, n_clusters

        def _simple_clustering(self, pts):
            """Simple distance-based clustering without sklearn."""
            if len(pts) < 3:
                return 1 if len(pts) > 0 else 0

            # Use hierarchical-like approach: group points that are close together
            visited = set()
            clusters = 0

            for i in range(len(pts)):
                if i in visited:
                    continue

                # Start a new cluster
                cluster = [i]
                clusters += 1

                # Find all points within distance threshold
                stack = [i]
                while stack:
                    current = stack.pop()
                    if current in visited:
                        continue
                    visited.add(current)

                    for j in range(len(pts)):
                        if j not in visited:
                            dist = np.linalg.norm(pts[current] - pts[j])
                            if dist < 50:  # 50px threshold for cluster
                                stack.append(j)

            return clusters

        def _draw_results(self, img, pairs, mask):
            """Annotate image with detected regions."""
            overlay = img.copy()

            # Red overlay on suspicious regions
            if mask is not None:
                red_layer = np.zeros_like(img)
                red_layer[mask > 0] = [0, 0, 200]
                cv2.addWeighted(red_layer, 0.35, overlay, 0.65, 0, overlay)

            # Draw lines between copy-move pairs
            for pt1, pt2 in pairs[:50]:  # limit lines for clarity
                p1 = (int(pt1[0]), int(pt1[1]))
                p2 = (int(pt2[0]), int(pt2[1]))
                cv2.line(overlay, p1, p2, (0, 255, 255), 1, cv2.LINE_AA)
                cv2.circle(overlay, p1, 4, (0, 0, 255), -1)
                cv2.circle(overlay, p2, 4, (255, 165, 0), -1)

            # Label
            cv2.putText(
                overlay, "FORGERY DETECTED",
                (10, 30), cv2.FONT_HERSHEY_DUPLEX, 0.9,
                (0, 0, 255), 2, cv2.LINE_AA
            )
            return overlay

        def _no_detection_result(self, img, image_path):
            annotated = img.copy()
            cv2.putText(
                annotated, "NO FORGERY DETECTED",
                (10, 30), cv2.FONT_HERSHEY_DUPLEX, 0.9,
                (0, 200, 0), 2, cv2.LINE_AA
            )
            result_path = image_path.replace("uploads", "results").replace(
                os.path.splitext(image_path)[-1], "_result.jpg"
            )
            cv2.imwrite(result_path, annotated)
            return {
                "detected": False,
                "confidence": 0,
                "total_keypoints": 0,
                "total_matches": 0,
                "suspicious_pairs": 0,
                "clusters_found": 0,
                "result_image": result_path,
                "message": "No copy-move forgery detected. Image appears authentic.",
            }


def main():
    import argparse, json

    parser = argparse.ArgumentParser(
        description="Run copy-move forgery detection on a single image."
    )
    parser.add_argument("image", help="Path to input image")
    parser.add_argument(
        "-m", "--method", choices=["SIFT", "ORB"], default="SIFT",
        help="feature detection method (default: SIFT)"
    )
    args = parser.parse_args()

    detector = CopyMoveDetector(method=args.method)
    try:
        result = detector.detect(args.image)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return

    # print result as JSON
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
